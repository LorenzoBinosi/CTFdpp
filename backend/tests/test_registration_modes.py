import copy
import unittest

from test_app import BOOTSTRAP, FakeApi, make_app


class RegistrationModeTests(unittest.TestCase):
    def render_registration(self, mode="open", **site_values):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["site"].update(site_values)
        if mode is None:
            bootstrap["data"]["site"].pop("registration_access_mode", None)
        else:
            bootstrap["data"]["site"]["registration_access_mode"] = mode
        client = make_app(FakeApi(bootstrap=bootstrap)).test_client()
        response = client.get("/register")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def test_access_code_mode_requires_the_registration_code_field(self):
        body = self.render_registration("access_code")

        self.assertIn('<label for="registration_code">Registration code</label>', body)
        self.assertIn(
            'name="registration_code" type="text" autocomplete="off" required',
            body,
        )
        self.assertNotIn("Registration code <span", body)

    def test_open_mode_omits_registration_policy_controls(self):
        body = self.render_registration("open")

        self.assertNotIn('name="registration_code"', body)
        self.assertNotIn("restricted by email domain", body)
        self.assertNotIn("limited to invited email addresses", body)

    def test_domain_rules_show_only_neutral_guidance(self):
        body = self.render_registration(
            "domain_rules",
            domain_whitelist="private.example",
            domain_blacklist="blocked.example",
            registration_code="do-not-render",
        )

        self.assertNotIn('name="registration_code"', body)
        self.assertIn("Registration is restricted by email domain", body)
        self.assertNotIn("private.example", body)
        self.assertNotIn("blocked.example", body)
        self.assertNotIn("do-not-render", body)

    def test_email_allowlist_shows_only_invitation_guidance(self):
        body = self.render_registration(
            "email_allowlist",
            registration_email_allowlist=["invited@example.test"],
        )

        self.assertNotIn('name="registration_code"', body)
        self.assertIn("Registration is limited to invited email addresses", body)
        self.assertIn("exact address associated with your invitation", body)
        self.assertNotIn("invited@example.test", body)

    def test_missing_or_unknown_modes_safely_fall_back_to_open(self):
        for mode in (None, "", "ACCESS_CODE", "unknown", ["access_code"]):
            with self.subTest(mode=mode):
                body = self.render_registration(mode)
                self.assertNotIn('name="registration_code"', body)
                self.assertNotIn("restricted by email domain", body)
                self.assertNotIn("limited to invited email addresses", body)


if __name__ == "__main__":
    unittest.main()
