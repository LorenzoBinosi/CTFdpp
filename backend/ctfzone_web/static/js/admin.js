import { apiRequest, idempotencyHeaders } from "./api.js";
import { showToast } from "./app.js";

const menuButton = document.querySelector("[data-admin-menu]");
const sidebar = document.querySelector("[data-admin-sidebar]");
const sidebarBackdrop = document.querySelector("[data-admin-backdrop]");

function setSidebar(open) {
  sidebar?.classList.toggle("open", open);
  sidebarBackdrop?.classList.toggle("open", open);
  menuButton?.setAttribute("aria-expanded", String(open));
}

menuButton?.addEventListener("click", () => setSidebar(!sidebar?.classList.contains("open")));
sidebarBackdrop?.addEventListener("click", () => setSidebar(false));
document.addEventListener("keydown", event => {
  if (event.key === "Escape") setSidebar(false);
});

for (const input of document.querySelectorAll("[data-admin-table-search]")) {
  const table = input.closest(".admin-panel")?.querySelector("[data-admin-table]");
  input.addEventListener("input", () => {
    const query = input.value.trim().toLocaleLowerCase();
    for (const row of table?.tBodies[0]?.rows || []) {
      row.hidden = Boolean(query) && !row.textContent.toLocaleLowerCase().includes(query);
    }
  });
}

const configSearch = document.querySelector("[data-config-search]");
configSearch?.addEventListener("input", () => {
  const query = configSearch.value.trim().toLocaleLowerCase();
  for (const row of document.querySelectorAll("[data-config-form]")) {
    row.hidden = Boolean(query) && !row.dataset.configKey.toLocaleLowerCase().includes(query);
  }
});

function setBusy(button, busy, label = "Saving…") {
  if (!button) return;
  if (busy) {
    button.dataset.originalLabel = button.textContent;
    button.textContent = label;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalLabel || button.textContent;
    button.disabled = false;
  }
}

function asNumber(form, name, fallback = 0) {
  const value = form.elements[name]?.value?.trim();
  return value === "" || value === undefined ? fallback : Number(value);
}

const challengeForm = document.querySelector("[data-challenge-form]");
if (challengeForm) {
  const typeField = challengeForm.elements.type;
  const dynamicFields = challengeForm.querySelector("[data-dynamic-fields]");
  const syncChallengeType = () => {
    const dynamic = typeField?.value === "dynamic";
    dynamicFields?.classList.toggle("visible", dynamic);
    for (const input of dynamicFields?.querySelectorAll("input, select") || []) input.disabled = !dynamic;
  };
  typeField?.addEventListener("change", syncChallengeType);
  syncChallengeType();

  challengeForm.addEventListener("submit", async event => {
    event.preventDefault();
    if (!challengeForm.reportValidity()) return;
    const submit = challengeForm.querySelector('button[type="submit"]');
    setBusy(submit, true);

    const dynamic = typeField?.value === "dynamic";
    const payload = {
      name: challengeForm.elements.name.value.trim(),
      category: challengeForm.elements.category.value.trim(),
      description: challengeForm.elements.description.value,
      connection_info: challengeForm.elements.connection_info.value.trim() || null,
      type: typeField?.value || "standard",
      function: dynamic ? challengeForm.elements.function.value : "static",
      value: dynamic ? asNumber(challengeForm, "initial", 500) : asNumber(challengeForm, "value", 500),
      state: challengeForm.elements.state.value,
      logic: "any",
      max_attempts: asNumber(challengeForm, "max_attempts", 0),
      position: asNumber(challengeForm, "position", 0),
    };
    if (dynamic) {
      payload.initial = asNumber(challengeForm, "initial", 500);
      payload.minimum = asNumber(challengeForm, "minimum", 100);
      payload.decay = asNumber(challengeForm, "decay", 50);
    }

    try {
      const mode = challengeForm.dataset.mode;
      const path = mode === "create"
        ? "/api/v1/challenges"
        : `/api/v1/challenges/${challengeForm.dataset.challengeId}`;
      const result = await apiRequest(path, {
        method: mode === "create" ? "POST" : "PATCH",
        headers: mode === "create" ? idempotencyHeaders() : undefined,
        body: payload,
      });
      const challengeId = result.data?.id || challengeForm.dataset.challengeId;
      const flag = challengeForm.elements.flag?.value?.trim();
      if (mode === "create" && flag && challengeId) {
        try {
          await apiRequest("/api/v1/flags", {
            method: "POST",
            headers: idempotencyHeaders(),
            body: { challenge_id: Number(challengeId), type: "static", content: flag, data: null },
          });
        } catch (error) {
          showToast(`Challenge created, but its flag was not saved: ${error.message}`, "warning", 6000);
          window.setTimeout(() => { window.location.href = `/admin/challenges/${challengeId}`; }, 900);
          return;
        }
      }
      showToast(mode === "create" ? "Challenge created." : "Challenge updated.");
      window.setTimeout(() => { window.location.href = "/admin/challenges"; }, 350);
    } catch (error) {
      showToast(error.message || "The challenge could not be saved.", "error", 5500);
      setBusy(submit, false);
    }
  });

  challengeForm.querySelector("[data-delete-challenge]")?.addEventListener("click", async event => {
    const challengeId = challengeForm.dataset.challengeId;
    if (!challengeId || !window.confirm("Delete this challenge and its dependent records? This cannot be undone.")) return;
    setBusy(event.currentTarget, true, "Deleting…");
    try {
      await apiRequest(`/api/v1/challenges/${challengeId}`, { method: "DELETE" });
      showToast("Challenge deleted.");
      window.setTimeout(() => { window.location.href = "/admin/challenges"; }, 350);
    } catch (error) {
      showToast(error.message || "The challenge could not be deleted.", "error", 5500);
      setBusy(event.currentTarget, false);
    }
  });
}

for (const form of document.querySelectorAll("[data-config-form]")) {
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const input = form.elements.value;
    const button = form.querySelector('button[type="submit"]');
    let value = input.value;
    try {
      if (input.dataset.valueType === "boolean") value = value === "true";
      if (input.dataset.valueType === "number") value = Number(value);
      if (input.dataset.valueType === "json") value = JSON.parse(value);
    } catch (_error) {
      showToast("Enter valid JSON before saving this setting.", "error");
      return;
    }
    setBusy(button, true);
    try {
      await apiRequest(`/api/v1/configs/${encodeURIComponent(form.dataset.configKey)}`, {
        method: "PATCH",
        body: { value },
      });
      showToast(`${form.dataset.configKey} updated.`);
    } catch (error) {
      showToast(error.message || "The setting could not be saved.", "error", 5500);
    } finally {
      setBusy(button, false);
    }
  });
}

const runtimeSetting = document.querySelector("[data-runtime-setting]");
runtimeSetting?.addEventListener("change", async () => {
  const previous = !runtimeSetting.checked;
  runtimeSetting.disabled = true;
  try {
    await apiRequest("/api/v1/admin/runtime/settings/private-challenges", {
      method: "PATCH",
      body: { enabled: runtimeSetting.checked },
    });
    const label = document.querySelector("[data-runtime-setting-label]");
    if (label) label.textContent = runtimeSetting.checked ? "Enabled" : "Disabled";
    showToast(`Private challenge instances ${runtimeSetting.checked ? "enabled" : "disabled"}.`);
  } catch (error) {
    runtimeSetting.checked = previous;
    showToast(error.message || "The runtime setting could not be changed.", "error", 5500);
  } finally {
    runtimeSetting.disabled = false;
  }
});

for (const button of document.querySelectorAll("[data-reconcile-instance]")) {
  button.addEventListener("click", async () => {
    setBusy(button, true, "Queued…");
    try {
      await apiRequest(`/api/v1/admin/runtime/instances/${button.dataset.reconcileInstance}/reconcile`, { method: "POST" });
      showToast("Reconciliation queued for the controller.");
    } catch (error) {
      showToast(error.message || "Reconciliation could not be queued.", "error", 5500);
    } finally {
      setBusy(button, false);
    }
  });
}

for (const button of document.querySelectorAll("[data-terminate-instance]")) {
  button.addEventListener("click", async () => {
    if (!window.confirm("Request termination of this managed instance?")) return;
    setBusy(button, true, "Stopping…");
    try {
      await apiRequest(`/api/v1/instances/${button.dataset.terminateInstance}/terminate`, { method: "POST" });
      showToast("Termination requested. The controller will reconcile it asynchronously.");
      window.setTimeout(() => window.location.reload(), 600);
    } catch (error) {
      showToast(error.message || "Termination could not be requested.", "error", 5500);
      setBusy(button, false);
    }
  });
}
