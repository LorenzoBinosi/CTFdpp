from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
import pathlib
import tempfile
import threading
import unittest
from unittest import mock


HELPER_PATH = pathlib.Path(__file__).with_name("ctfzone-runtime-helper")
LOADER = SourceFileLoader("ctfzone_runtime_helper", str(HELPER_PATH))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load runtime helper")
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)

INSTANCE_ID = "11111111-1111-4111-8111-111111111111"


class GenerationSafetyTests(unittest.TestCase):
    def test_elapsed_deadline_cannot_create_an_unprotected_generation(self) -> None:
        elapsed = helper.dt.datetime.now(helper.dt.timezone.utc) - helper.dt.timedelta(
            seconds=1
        )
        with self.assertRaises(helper.HelperError):
            helper.schedule_timer(INSTANCE_ID, 4, elapsed)

    def test_stale_stop_does_not_remove_newer_generation(self) -> None:
        with (
            mock.patch.object(helper, "inspect_raw", return_value={}),
            mock.patch.object(
                helper,
                "read_state",
                return_value={"instance_id": INSTANCE_ID, "generation": 7},
            ),
            mock.patch.object(helper, "remove_workload_verified") as remove,
        ):
            result = helper.stop_instance(
                {"instance_id": INSTANCE_ID, "generation": 6}
            )

        self.assertEqual(result["stale_generation"], True)
        self.assertEqual(result["effective_generation"], 7)
        remove.assert_not_called()

    def test_stop_verifies_removal_before_cancelling_timer(self) -> None:
        calls: list[str] = []
        with (
            mock.patch.object(helper, "inspect_raw", return_value={}),
            mock.patch.object(
                helper,
                "read_state",
                return_value={"instance_id": INSTANCE_ID, "generation": 4},
            ),
            mock.patch.object(
                helper,
                "remove_container_verified",
                side_effect=lambda _identifier: calls.append("remove"),
            ),
            mock.patch.object(
                helper,
                "write_tombstone",
                side_effect=lambda *_arguments: calls.append("tombstone"),
            ),
            mock.patch.object(
                helper,
                "remove_network_verified",
                side_effect=lambda _identifier: calls.append("network"),
            ),
            mock.patch.object(
                helper,
                "cancel_timer",
                side_effect=lambda *_arguments: calls.append("cancel"),
            ),
            mock.patch.object(
                helper,
                "remove_state",
                side_effect=lambda _identifier: calls.append("state"),
            ),
        ):
            result = helper.stop_instance(
                {"instance_id": INSTANCE_ID, "generation": 5}
            )

        self.assertEqual(result["absent"], True)
        self.assertEqual(calls[0], "tombstone")
        self.assertEqual(calls[1], "remove")
        self.assertEqual(calls[2], "network")
        self.assertEqual(calls[-1], "state")

    def test_failed_removal_preserves_timer_and_state(self) -> None:
        with (
            mock.patch.object(helper, "inspect_raw", return_value={}),
            mock.patch.object(
                helper,
                "read_state",
                return_value={"instance_id": INSTANCE_ID, "generation": 4},
            ),
            mock.patch.object(
                helper,
                "remove_container_verified",
                side_effect=helper.HelperError("still present"),
            ),
            mock.patch.object(helper, "write_tombstone"),
            mock.patch.object(helper, "cancel_timer") as cancel,
            mock.patch.object(helper, "remove_state") as remove_state,
        ):
            with self.assertRaises(helper.HelperError):
                helper.stop_instance({"instance_id": INSTANCE_ID, "generation": 5})

        cancel.assert_not_called()
        remove_state.assert_not_called()

    def test_stop_accepts_verified_fail_closed_removal_after_state_loss(self) -> None:
        inspection = {
            "Config": {
                "Labels": {
                    "ctfzone.instance_id": INSTANCE_ID,
                    "ctfzone.generation": "4",
                }
            }
        }
        with (
            mock.patch.object(helper, "inspect_raw", return_value=inspection),
            mock.patch.object(
                helper,
                "read_state",
                side_effect=helper.HelperError("state corrupt"),
            ),
            mock.patch.object(
                helper, "remove_irrecoverable_instance_unlocked"
            ) as remove,
        ):
            result = helper.stop_instance(
                {"instance_id": INSTANCE_ID, "generation": 5}
            )

        self.assertEqual(result["absent"], True)
        self.assertEqual(result["stale_generation"], False)
        remove.assert_called_once_with(INSTANCE_ID, inspection)

    def test_deadline_replacement_is_installed_before_state_switch(self) -> None:
        calls: list[str] = []
        state = {
            "instance_id": INSTANCE_ID,
            "generation": 2,
            "expires_at": "2099-01-01T00:00:00Z",
            "deployment": {},
        }
        request = {
            "instance_id": INSTANCE_ID,
            "generation": 3,
            "expires_at": "2099-01-01T01:00:00Z",
        }
        with (
            mock.patch.object(helper, "read_state", return_value=state),
            mock.patch.object(helper, "inspect_raw", return_value={}),
            mock.patch.object(
                helper,
                "schedule_timer",
                side_effect=lambda *_arguments: calls.append("schedule"),
            ),
            mock.patch.object(
                helper,
                "write_state",
                side_effect=lambda *_arguments: calls.append("state"),
            ),
            mock.patch.object(
                helper,
                "cancel_timer",
                side_effect=lambda *_arguments: calls.append("cancel"),
            ),
        ):
            result = helper.update_deadline(request)

        self.assertEqual(result["effective_generation"], 3)
        self.assertEqual(calls, ["schedule", "state", "cancel"])

    def test_extension_fails_closed_when_durable_state_is_missing(self) -> None:
        inspection = {
            "Config": {
                "Labels": {
                    "ctfzone.instance_id": INSTANCE_ID,
                    "ctfzone.generation": "3",
                }
            }
        }
        with (
            mock.patch.object(helper, "read_tombstone", return_value=None),
            mock.patch.object(helper, "inspect_raw", return_value=inspection),
            mock.patch.object(helper, "read_state", return_value=None),
            mock.patch.object(
                helper, "remove_irrecoverable_instance_unlocked"
            ) as remove,
        ):
            result = helper.update_deadline(
                {
                    "instance_id": INSTANCE_ID,
                    "generation": 4,
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            )

        self.assertEqual(result["absent"], True)
        self.assertEqual(result["stale_generation"], True)
        remove.assert_called_once_with(INSTANCE_ID, inspection)

    def test_delayed_ensure_cannot_resurrect_a_stopped_uuid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tombstones = pathlib.Path(directory) / "tombstones"
            with (
                mock.patch.object(helper, "TOMBSTONES_DIRECTORY", tombstones),
                mock.patch.object(helper, "inspect_raw", return_value={}),
                mock.patch.object(
                    helper,
                    "read_state",
                    return_value={"instance_id": INSTANCE_ID, "generation": 2},
                ),
                mock.patch.object(helper, "remove_workload_verified"),
                mock.patch.object(helper, "cancel_timer"),
                mock.patch.object(helper, "remove_state"),
            ):
                helper.stop_instance({"instance_id": INSTANCE_ID, "generation": 2})

            with (
                mock.patch.object(helper, "TOMBSTONES_DIRECTORY", tombstones),
                mock.patch.object(helper, "inspect_raw", return_value=None),
                mock.patch.object(helper, "ensure_network") as ensure_network,
            ):
                result = helper.ensure_instance(
                    {"instance_id": INSTANCE_ID, "generation": 2}
                )

        self.assertEqual(result["stale_generation"], True)
        self.assertEqual(result["absent"], True)
        self.assertEqual(result["effective_generation"], 2)
        ensure_network.assert_not_called()

    def test_network_name_is_unique_per_instance(self) -> None:
        other = "22222222-2222-4222-8222-222222222222"
        first = helper.network_name(INSTANCE_ID)
        second = helper.network_name(other)
        self.assertNotEqual(first, second)
        self.assertLessEqual(len(first), 63)


class StartupHealthTests(unittest.TestCase):
    def test_waits_until_container_health_is_healthy(self) -> None:
        inspections = iter(
            [
                {"State": {"Running": True, "Health": {"Status": "starting"}}},
                {"State": {"Running": True, "Health": {"Status": "healthy"}}},
            ]
        )
        with (
            mock.patch.object(helper, "inspect_raw", side_effect=lambda _id: next(inspections)),
            mock.patch.object(helper.time, "sleep"),
        ):
            helper.wait_for_startup(
                INSTANCE_ID,
                {"command": "true", "startup_timeout_seconds": 5},
            )

    def test_inspection_does_not_report_an_exited_container_ready(self) -> None:
        inspection = {
            "Config": {"Labels": {"ctfzone.instance_id": INSTANCE_ID}},
            "State": {"Running": False, "Status": "exited"},
            "NetworkSettings": {},
        }
        state = {
            "instance_id": INSTANCE_ID,
            "generation": 2,
            "expires_at": "2099-01-01T00:00:00Z",
            "deployment": {"container_port": 31337, "protocol": "tcp"},
        }
        with (
            mock.patch.object(helper, "inspect_raw", return_value=inspection),
            mock.patch.object(helper, "read_state", return_value=state),
        ):
            result = helper.inspect_result(INSTANCE_ID)

        self.assertEqual(result["absent"], False)
        self.assertEqual(result["ready"], False)
        self.assertEqual(result["runtime_status"], "exited")

    def test_inspection_requires_configured_healthcheck_to_be_healthy(self) -> None:
        inspection = {
            "Config": {"Labels": {"ctfzone.instance_id": INSTANCE_ID}},
            "State": {
                "Running": True,
                "Status": "running",
                "Health": {"Status": "unhealthy"},
            },
            "NetworkSettings": {},
        }
        state = {
            "instance_id": INSTANCE_ID,
            "generation": 2,
            "expires_at": "2099-01-01T00:00:00Z",
            "deployment": {
                "container_port": 31337,
                "protocol": "tcp",
                "healthcheck": {"command": "true"},
            },
        }
        with (
            mock.patch.object(helper, "inspect_raw", return_value=inspection),
            mock.patch.object(helper, "read_state", return_value=state),
        ):
            result = helper.inspect_result(INSTANCE_ID)

        self.assertEqual(result["ready"], False)
        self.assertEqual(result["health_status"], "unhealthy")

    def test_direct_inspection_removes_workload_when_state_is_lost(self) -> None:
        inspection = {
            "Config": {
                "Labels": {
                    "ctfzone.instance_id": INSTANCE_ID,
                    "ctfzone.generation": "7",
                    "ctfzone.expires_at": "2099-01-01T00:00:00Z",
                }
            },
            "State": {"Running": True, "Health": {"Status": "healthy"}},
        }
        with (
            mock.patch.object(helper, "inspect_raw", return_value=inspection),
            mock.patch.object(helper, "read_state", return_value=None),
            mock.patch.object(
                helper, "remove_irrecoverable_instance_unlocked"
            ) as remove,
        ):
            result = helper.inspect_result(INSTANCE_ID)

        self.assertEqual(result["absent"], True)
        self.assertEqual(result["ready"], False)
        self.assertEqual(result["effective_generation"], 7)
        remove.assert_called_once_with(INSTANCE_ID, inspection)


class SweepRecoveryTests(unittest.TestCase):
    def test_irrecoverable_deadline_metadata_removes_workload_fail_closed(self) -> None:
        inspection = {
            "Config": {"Labels": {"ctfzone.instance_id": INSTANCE_ID}}
        }
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(
                    helper, "INSTANCES_DIRECTORY", pathlib.Path(directory) / "instances"
                ),
                mock.patch.object(
                    helper, "managed_container_identifiers", return_value={INSTANCE_ID}
                ),
                mock.patch.object(helper, "managed_network_identifiers", return_value=set()),
                mock.patch.object(helper, "inspect_raw", return_value=inspection),
                mock.patch.object(helper, "read_state", return_value=None),
                mock.patch.object(helper, "remove_workload_verified") as remove,
                mock.patch.object(helper, "write_tombstone"),
                mock.patch.object(helper, "cancel_timer"),
            ):
                result = helper.sweep_instances()

        self.assertEqual(result, {"checked": 1, "removed": 1, "rearmed": 0})
        remove.assert_called_once_with(INSTANCE_ID)

    def test_extended_container_with_missing_state_is_removed_fail_closed(self) -> None:
        inspection = {
            "Config": {
                "Labels": {
                    "ctfzone.instance_id": INSTANCE_ID,
                    "ctfzone.generation": "4",
                    "ctfzone.expires_at": "2099-01-01T00:00:00Z",
                }
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            state_directory = pathlib.Path(directory) / "instances"
            with (
                mock.patch.object(helper, "INSTANCES_DIRECTORY", state_directory),
                mock.patch.object(
                    helper, "managed_container_identifiers", return_value={INSTANCE_ID}
                ),
                mock.patch.object(helper, "managed_network_identifiers", return_value=set()),
                mock.patch.object(helper, "inspect_raw", return_value=inspection),
                mock.patch.object(helper, "read_state", return_value=None),
                mock.patch.object(helper, "write_tombstone") as tombstone,
                mock.patch.object(helper, "remove_workload_verified") as remove,
                mock.patch.object(helper, "cancel_timer"),
                mock.patch.object(helper, "remove_state"),
            ):
                result = helper.sweep_instances()

            self.assertEqual(result, {"checked": 1, "removed": 1, "rearmed": 0})
            tombstone.assert_called_once_with(INSTANCE_ID, 4)
            remove.assert_called_once_with(INSTANCE_ID)

    def test_healthchecked_container_with_corrupt_state_is_removed(self) -> None:
        inspection = {
            "Config": {
                "Labels": {
                    "ctfzone.instance_id": INSTANCE_ID,
                    "ctfzone.generation": "4",
                    "ctfzone.expires_at": "2099-01-01T00:00:00Z",
                }
            },
            "State": {"Running": True, "Health": {"Status": "healthy"}},
        }
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(
                    helper, "INSTANCES_DIRECTORY", pathlib.Path(directory) / "instances"
                ),
                mock.patch.object(
                    helper, "managed_container_identifiers", return_value={INSTANCE_ID}
                ),
                mock.patch.object(helper, "managed_network_identifiers", return_value=set()),
                mock.patch.object(helper, "inspect_raw", return_value=inspection),
                mock.patch.object(
                    helper,
                    "read_state",
                    side_effect=helper.HelperError("instance state is unreadable"),
                ),
                mock.patch.object(helper, "write_tombstone") as tombstone,
                mock.patch.object(helper, "remove_workload_verified") as remove,
                mock.patch.object(helper, "cancel_timer"),
                mock.patch.object(helper, "remove_state"),
            ):
                result = helper.sweep_instances()

        self.assertEqual(result, {"checked": 1, "removed": 1, "rearmed": 0})
        tombstone.assert_called_once_with(INSTANCE_ID, 4)
        remove.assert_called_once_with(INSTANCE_ID)

    def test_orphan_network_is_discovered_and_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(
                    helper, "INSTANCES_DIRECTORY", pathlib.Path(directory) / "instances"
                ),
                mock.patch.object(helper, "managed_container_identifiers", return_value=set()),
                mock.patch.object(
                    helper, "managed_network_identifiers", return_value={INSTANCE_ID}
                ),
                mock.patch.object(helper, "inspect_raw", return_value=None),
                mock.patch.object(helper, "read_state", return_value=None),
                mock.patch.object(helper, "remove_network_verified") as remove_network,
                mock.patch.object(helper, "remove_state"),
                mock.patch.object(helper, "cancel_timer"),
            ):
                result = helper.sweep_instances()

        self.assertEqual(result, {"checked": 1, "removed": 0, "rearmed": 0})
        remove_network.assert_called_once_with(INSTANCE_ID)


class LockingTests(unittest.TestCase):
    def test_instance_operations_are_serialized(self) -> None:
        acquired = threading.Event()
        with tempfile.TemporaryDirectory() as directory:
            instances = pathlib.Path(directory) / "instances"
            with mock.patch.object(helper, "INSTANCES_DIRECTORY", instances):
                with helper.instance_lock(INSTANCE_ID):
                    contender = threading.Thread(
                        target=lambda: self._acquire_lock(acquired), daemon=True
                    )
                    contender.start()
                    self.assertFalse(acquired.wait(0.05))
                self.assertTrue(acquired.wait(1))
                contender.join(timeout=1)

    @staticmethod
    def _acquire_lock(acquired: threading.Event) -> None:
        with helper.instance_lock(INSTANCE_ID):
            acquired.set()


if __name__ == "__main__":
    unittest.main()
