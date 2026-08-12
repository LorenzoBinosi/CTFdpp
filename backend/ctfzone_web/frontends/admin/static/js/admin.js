import { apiRequest, idempotencyHeaders } from "/assets/shared/js/api.js";
import { showToast } from "/assets/shared/js/ui.js";
import { uploadObject } from "/assets/shared/js/storage.js";

const menuButton = document.querySelector("[data-admin-menu]");
const sidebar = document.querySelector("[data-admin-sidebar]");
const sidebarBackdrop = document.querySelector("[data-admin-backdrop]");
const mobileSidebarQuery = window.matchMedia("(max-width: 980px)");
const reducedMotionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
let sidebarReturnFocus = null;

function sidebarFocusables() {
  return Array.from(sidebar?.querySelectorAll(
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
  ) || []).filter(control => !control.hidden);
}

function syncSidebarAccessibility(open) {
  if (!sidebar) return;
  const hidden = mobileSidebarQuery.matches && !open;
  sidebar.toggleAttribute("inert", hidden);
  if (hidden) sidebar.setAttribute("aria-hidden", "true");
  else sidebar.removeAttribute("aria-hidden");
}

function setSidebar(open, { restoreFocus = true } = {}) {
  const wasOpen = Boolean(sidebar?.classList.contains("open"));
  if (open && !wasOpen && document.activeElement instanceof HTMLElement) {
    sidebarReturnFocus = document.activeElement;
  }
  sidebar?.classList.toggle("open", open);
  syncSidebarAccessibility(open);
  sidebarBackdrop?.classList.toggle("open", open);
  sidebarBackdrop?.setAttribute("aria-hidden", String(!open));
  if (sidebarBackdrop) sidebarBackdrop.tabIndex = open ? 0 : -1;
  menuButton?.setAttribute("aria-expanded", String(open));
  if (open && !wasOpen) {
    const focusSidebar = () => sidebarFocusables()[0]?.focus({ preventScroll: true });
    if (reducedMotionQuery.matches) focusSidebar();
    else window.requestAnimationFrame(focusSidebar);
  } else if (!open && wasOpen) {
    if (restoreFocus) {
      const target = sidebarReturnFocus?.isConnected ? sidebarReturnFocus : menuButton;
      target?.focus({ preventScroll: true });
    }
    sidebarReturnFocus = null;
  }
}

menuButton?.addEventListener("click", () => setSidebar(!sidebar?.classList.contains("open")));
sidebarBackdrop?.addEventListener("click", () => setSidebar(false));
document.addEventListener("keydown", event => {
  if (!sidebar?.classList.contains("open")) return;
  if (event.key === "Escape") {
    event.preventDefault();
    setSidebar(false);
    return;
  }
  if (event.key !== "Tab" || !mobileSidebarQuery.matches) return;
  const focusables = sidebarFocusables();
  if (!focusables.length) return;
  const first = focusables[0];
  const last = focusables[focusables.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
});
mobileSidebarQuery.addEventListener("change", () => {
  setSidebar(false, { restoreFocus: false });
});
sidebarBackdrop?.setAttribute("aria-hidden", "true");
if (sidebarBackdrop) sidebarBackdrop.tabIndex = -1;
syncSidebarAccessibility(false);

for (const input of document.querySelectorAll("[data-admin-table-search]")) {
  const table = input.closest(".admin-panel")?.querySelector("[data-admin-table]");
  input.addEventListener("input", () => {
    const query = input.value.trim().toLocaleLowerCase();
    for (const row of table?.tBodies[0]?.rows || []) {
      row.hidden = Boolean(query) && !row.textContent.toLocaleLowerCase().includes(query);
    }
  });
}

const configTabs = document.querySelector("[data-config-tabs]");
const configTabButtons = Array.from(configTabs?.querySelectorAll("[data-config-tab]") || []);
const configPanels = Array.from(document.querySelectorAll("[data-config-panel]"));
const configSearch = document.querySelector("[data-config-search]");
const firstConfigSection = configPanels.find(panel => panel.dataset.configPanel === "site")
  || configPanels[0];
let selectedConfigPanel = firstConfigSection?.dataset.configPanel
  || configPanels[0]?.dataset.configPanel
  || "all";

function configPanelFromHash() {
  let fragment = "";
  try { fragment = decodeURIComponent(window.location.hash.slice(1)); } catch (_error) { fragment = ""; }
  const direct = configPanels.find(
    panel => panel.id === fragment || panel.dataset.configPanel === fragment,
  );
  const nested = fragment ? document.getElementById(fragment)?.closest("[data-config-panel]") : null;
  if (direct || nested) return (direct || nested)?.dataset.configPanel;
  // The API combined the former Registration and Accounts sections. Keep old
  // bookmarks useful while the catalog remains the source of the new section.
  const legacyAlias = new Map([
    ["registration", "accounts"],
    ["config-registration", "accounts"],
  ]).get(fragment);
  return configPanels.some(panel => panel.dataset.configPanel === legacyAlias)
    ? legacyAlias
    : undefined;
}

function updateConfigHash(selection) {
  if (!window.history?.replaceState) return;
  const panel = configPanels.find(candidate => candidate.dataset.configPanel === selection);
  const url = new URL(window.location.href);
  url.hash = selection === "all" || !panel?.id ? "" : panel.id;
  window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
}

function renderConfigPanels() {
  const query = configSearch?.value.trim().toLocaleLowerCase() || "";
  const displayedSelection = query ? "all" : selectedConfigPanel;
  for (const entry of document.querySelectorAll("[data-config-searchable]")) {
    const matches = !query
      || (entry.dataset.configSearchText || "").toLocaleLowerCase().includes(query);
    entry.classList.toggle("search-hidden", !matches);
    // Search may reveal an inactive policy editor for discovery, but dependency
    // synchronization keeps its controls disabled until that policy is selected.
    entry.classList.toggle("search-reveal", Boolean(query) && matches);
  }
  for (const group of document.querySelectorAll("[data-config-group]")) {
    const matchingSetting = group.querySelector("[data-config-searchable]:not(.search-hidden)");
    group.classList.toggle("search-hidden", Boolean(query) && !matchingSetting);
    group.classList.toggle("search-reveal", Boolean(query) && Boolean(matchingSetting));
  }

  for (const button of configTabButtons) {
    const active = button.dataset.configTab === displayedSelection;
    button.setAttribute("aria-pressed", String(active));
    if (active) button.setAttribute("aria-current", "true");
    else button.removeAttribute("aria-current");
  }

  for (const panel of configPanels) {
    const selected = displayedSelection === "all" || panel.dataset.configPanel === displayedSelection;
    const matchingSetting = panel.querySelector("[data-config-searchable]:not(.search-hidden)");
    const matchesSearch = !query || Boolean(matchingSetting);
    panel.classList.toggle("search-hidden", Boolean(query) && !matchesSearch);
    panel.hidden = !selected || !matchesSearch;
  }
}

function selectConfigPanel(selection, { updateHash = true, clearSearch = false } = {}) {
  const valid = selection === "all"
    || configPanels.some(panel => panel.dataset.configPanel === selection);
  if (!valid) return;
  if (clearSearch && configSearch?.value) configSearch.value = "";
  selectedConfigPanel = selection;
  renderConfigPanels();
  if (updateHash) updateConfigHash(selection);
}

for (const button of configTabButtons) {
  button.addEventListener("click", () => {
    selectConfigPanel(button.dataset.configTab, { clearSearch: true });
  });
}

configSearch?.addEventListener("input", renderConfigPanels);
window.addEventListener("hashchange", () => {
  const selection = configPanelFromHash();
  if (selection) selectConfigPanel(selection, { updateHash: false, clearSearch: true });
});

const hashedConfigPanel = configPanelFromHash();
if (hashedConfigPanel) {
  selectedConfigPanel = hashedConfigPanel;
  updateConfigHash(hashedConfigPanel);
}
renderConfigPanels();

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

async function uploadChallengeFiles(input, status, challengeId) {
  const files = Array.from(input?.files || []);
  if (!files.length) return 0;
  if (!Number.isSafeInteger(Number(challengeId)) || Number(challengeId) < 1) {
    throw new Error("The saved challenge did not return a valid identifier.");
  }
  for (const [index, file] of files.entries()) {
    if (status) status.textContent = `Uploading ${index + 1}/${files.length}: ${file.name}`;
    await uploadObject(file, {
      purpose: "challenge_asset",
      challenge_id: Number(challengeId),
    });
  }
  if (status) status.textContent = `${files.length} file${files.length === 1 ? "" : "s"} attached.`;
  return files.length;
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
      const fileInput = challengeForm.querySelector("[data-challenge-files]");
      const uploadStatus = challengeForm.querySelector("[data-upload-status]");
      let uploadedFiles = 0;
      try {
        uploadedFiles = await uploadChallengeFiles(fileInput, uploadStatus, challengeId);
      } catch (error) {
        if (uploadStatus) uploadStatus.textContent = `Upload stopped: ${error.message}`;
        showToast(
          `Challenge ${mode === "create" ? "created" : "updated"}, but its files were not all attached: ${error.message}`,
          "warning",
          7000,
        );
        if (mode === "create") {
          window.setTimeout(() => { window.location.href = `/admin/challenges/${challengeId}`; }, 1000);
        } else {
          setBusy(submit, false);
        }
        return;
      }
      const fileMessage = uploadedFiles
        ? ` ${uploadedFiles} file${uploadedFiles === 1 ? "" : "s"} attached.`
        : "";
      showToast(`${mode === "create" ? "Challenge created." : "Challenge updated."}${fileMessage}`);
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

function configInputValue(input) {
  const raw = input.value;
  switch (input.dataset.valueType) {
    case "boolean": return raw === "true";
    case "integer": {
      if (raw === "") return null;
      const value = Number(raw);
      if (!Number.isSafeInteger(value)) throw new Error("Enter a valid whole number.");
      return value;
    }
    case "number": {
      if (raw === "") return null;
      const value = Number(raw);
      if (!Number.isFinite(value)) throw new Error("Enter a valid number.");
      return value;
    }
    case "json": {
      try { return JSON.parse(raw); } catch (_error) { throw new Error("Enter valid JSON."); }
    }
    case "datetime": {
      if (!raw) return null;
      const milliseconds = new Date(raw).getTime();
      if (!Number.isFinite(milliseconds)) throw new Error("Enter a valid date and time.");
      return Math.floor(milliseconds / 1000);
    }
    default: return raw;
  }
}

function dependencyValue(key) {
  const input = Array.from(document.querySelectorAll("[data-config-input]"))
    .find(candidate => candidate.dataset.configKey === key);
  if (input) return input.value;
  const secret = Array.from(document.querySelectorAll("[data-secret-control]"))
    .find(candidate => candidate.dataset.configKey === key);
  if (!secret) return "";
  if (secret.querySelector("[data-secret-action]")?.value === "replace") {
    return secret.querySelector("[data-secret-value]")?.value || "";
  }
  return secret.dataset.configured === "true" ? "configured" : "";
}

function setConditionalState(dependent, visible) {
  dependent.classList.toggle("dependency-hidden", !visible);
  dependent.setAttribute("aria-disabled", String(!visible));
  const fieldset = dependent.querySelector(":scope > [data-conditional-fieldset]");
  if (fieldset) {
    fieldset.disabled = !visible;
    return;
  }
  for (const control of dependent.querySelectorAll("input, select, textarea")) {
    if (!visible || control.dataset.staticDisabled === "true") {
      control.disabled = true;
      continue;
    }
    if (control.matches("[data-secret-value]")) {
      control.disabled = dependent.querySelector("[data-secret-action]")?.value !== "replace";
    } else {
      control.disabled = false;
    }
  }
}

function syncConfigDependencies() {
  for (const dependent of document.querySelectorAll("[data-depends-key]")) {
    let expected = [];
    try { expected = JSON.parse(dependent.dataset.dependsValues || "[]").map(String); } catch (_error) { expected = []; }
    const actual = dependencyValue(dependent.dataset.dependsKey);
    let visible = expected.some(value => value === "configured" ? Boolean(actual) : value === actual);
    if (dependent.dataset.dependsNegate === "true") visible = !visible;
    setConditionalState(dependent, visible);
  }
  syncRegistrationPolicyGuide();
}

function syncRegistrationPolicyGuide() {
  const mode = dependencyValue("registration_access_mode") || "open";
  const options = Array.from(document.querySelectorAll("[data-registration-policy]"));
  for (const option of options) {
    const active = option.dataset.registrationPolicy === mode;
    option.classList.toggle("active", active);
    if (active) option.setAttribute("aria-current", "true");
    else option.removeAttribute("aria-current");
  }
  const activeOption = options.find(option => option.dataset.registrationPolicy === mode);
  const summary = document.querySelector("[data-registration-policy-summary]");
  if (summary) summary.textContent = activeOption?.querySelector("strong")?.textContent || "Open";
}

function markConfigSection(section) {
  let dirty = false;
  for (const input of section.querySelectorAll("[data-config-input]")) {
    if (!input.disabled && input.value !== input.dataset.initialControl) dirty = true;
  }
  for (const secret of section.querySelectorAll("[data-secret-control]")) {
    const action = secret.querySelector("[data-secret-action]");
    if (!action?.disabled && action.value !== "keep") dirty = true;
  }
  const status = section.querySelector("[data-config-save-status]");
  if (status) status.textContent = dirty ? "Unsaved changes" : "No unsaved changes";
  section.classList.toggle("dirty", dirty);
}

function localDatetimeValue(epochSeconds) {
  const date = new Date(Number(epochSeconds) * 1000);
  if (!Number.isFinite(date.getTime()) || Number(epochSeconds) <= 0) return "";
  const component = value => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${component(date.getMonth() + 1)}-${component(date.getDate())}`
    + `T${component(date.getHours())}:${component(date.getMinutes())}`;
}

for (const input of document.querySelectorAll("[data-config-input]")) {
  if (input.dataset.valueType === "datetime") {
    try { input.value = localDatetimeValue(JSON.parse(input.dataset.initial)); } catch (_error) { input.value = ""; }
  }
  input.dataset.initialControl = input.dataset.forceDirty === "true" ? "__stale_configuration__" : input.value;
}

for (const secret of document.querySelectorAll("[data-secret-control]")) {
  const action = secret.querySelector("[data-secret-action]");
  const replacement = secret.querySelector("[data-secret-value]");
  action?.addEventListener("change", () => {
    replacement.disabled = action.value !== "replace";
    replacement.required = action.value === "replace";
    if (action.value !== "replace") replacement.value = "";
    if (action.value === "replace") replacement.focus();
    markConfigSection(secret.closest("[data-config-section]"));
  });
}

for (const section of document.querySelectorAll("[data-config-section]")) {
  section.addEventListener("input", () => {
    syncConfigDependencies();
    renderConfigPanels();
    markConfigSection(section);
  });
  section.addEventListener("change", () => {
    syncConfigDependencies();
    renderConfigPanels();
    markConfigSection(section);
  });
  section.addEventListener("submit", async event => {
    event.preventDefault();
    if (!section.reportValidity()) return;
    const payload = {};
    const dangers = [];
    try {
      for (const input of section.querySelectorAll("[data-config-input]")) {
        if (input.disabled || input.value === input.dataset.initialControl) continue;
        payload[input.dataset.configKey] = configInputValue(input);
        const danger = input.closest("[data-config-setting]")?.dataset.configDanger;
        if (danger) dangers.push(danger);
      }
      for (const secret of section.querySelectorAll("[data-secret-control]")) {
        const action = secret.querySelector("[data-secret-action]");
        if (!action || action.disabled || action.value === "keep") continue;
        if (action.value === "replace") {
          const replacement = secret.querySelector("[data-secret-value]")?.value || "";
          if (!replacement) throw new Error(`Enter a replacement for ${secret.dataset.configKey}.`);
          payload[secret.dataset.configKey] = replacement;
        } else if (action.value === "clear") {
          if (!window.confirm(`Clear ${secret.dataset.configKey}? Services using it may stop working.`)) return;
          payload[secret.dataset.configKey] = null;
        }
      }
    } catch (error) {
      showToast(error.message || "Check this section's values.", "error", 5500);
      return;
    }
    const keys = Object.keys(payload);
    if (!keys.length) {
      showToast("There are no changes to save.", "warning");
      return;
    }
    if (dangers.length && !window.confirm(`${dangers.join("\n\n")}\n\nSave this change?`)) return;
    const buttons = section.querySelectorAll('button[type="submit"]');
    for (const button of buttons) setBusy(button, true);
    try {
      await apiRequest("/api/v1/configs", { method: "PATCH", body: payload });
      for (const input of section.querySelectorAll("[data-config-input]")) {
        if (Object.hasOwn(payload, input.dataset.configKey)) {
          input.dataset.initialControl = input.value;
          delete input.dataset.forceDirty;
        }
      }
      for (const secret of section.querySelectorAll("[data-secret-control]")) {
        if (!Object.hasOwn(payload, secret.dataset.configKey)) continue;
        secret.dataset.configured = String(payload[secret.dataset.configKey] !== null);
        const status = secret.querySelector("[data-secret-status]");
        status?.classList.toggle("good", secret.dataset.configured === "true");
        if (status) status.textContent = secret.dataset.configured === "true" ? "Configured" : "Not configured";
        secret.querySelector("[data-secret-action]").value = "keep";
        secret.querySelector("[data-secret-value]").value = "";
        secret.querySelector("[data-secret-value]").disabled = true;
      }
      markConfigSection(section);
      showToast(`${keys.length} setting${keys.length === 1 ? "" : "s"} saved atomically.`);
    } catch (error) {
      showToast(error.message || "This configuration section could not be saved.", "error", 5500);
    } finally {
      for (const button of buttons) setBusy(button, false);
    }
  });
}

syncConfigDependencies();
renderConfigPanels();
for (const section of document.querySelectorAll("[data-config-section]")) markConfigSection(section);

function updateAllowlistCount(delta = 0) {
  const panel = document.querySelector("[data-registration-allowlist]");
  const current = Number(panel?.dataset.allowlistTotal || 0);
  const count = Math.max(0, current + delta);
  if (panel) panel.dataset.allowlistTotal = String(count);
  const target = document.querySelector("[data-allowlist-count]");
  if (target) target.textContent = String(count);
}

function updateAllowlistEmpty() {
  const rendered = document.querySelectorAll("[data-allowlist-entry]").length;
  document.querySelector("[data-allowlist-empty]")?.toggleAttribute("hidden", rendered > 0);
}

function appendAllowlistEntry(entry, adjustTotal = true) {
  if (!entry || !Number.isSafeInteger(Number(entry.id)) || typeof entry.email !== "string") return;
  const row = document.createElement("tr");
  row.dataset.allowlistEntry = String(entry.id);
  const email = document.createElement("td");
  email.className = "mono";
  email.textContent = entry.email;
  const state = document.createElement("td");
  const pill = document.createElement("span");
  pill.className = `status-pill${entry.registered ? " good" : ""}`;
  pill.textContent = entry.registered ? "Registered" : "Invited";
  state.append(pill);
  const action = document.createElement("td");
  action.className = "table-actions";
  const button = document.createElement("button");
  button.className = "danger-button button-small";
  button.type = "button";
  button.dataset.allowlistDelete = String(entry.id);
  button.textContent = "Remove";
  button.disabled = Boolean(entry.registered);
  if (entry.registered) button.title = "Delete the registered account first";
  action.append(button);
  row.append(email, state, action);
  document.querySelector("[data-allowlist-body]")?.append(row);
  if (adjustTotal) updateAllowlistCount(1);
  updateAllowlistEmpty();
}

const allowlistPaging = { query: "", page: 1, pages: null };

async function loadAllowlistPage(page = 1) {
  const search = document.querySelector("[data-allowlist-search]");
  const previous = document.querySelector("[data-allowlist-previous]");
  const next = document.querySelector("[data-allowlist-next]");
  const status = document.querySelector("[data-allowlist-page-status]");
  const query = search?.elements.q.value.trim() || "";
  previous.disabled = true;
  next.disabled = true;
  if (status) status.textContent = "Loading…";
  try {
    const parameters = new URLSearchParams({ q: query, page: String(page), per_page: "50" });
    const result = await apiRequest(`/api/v1/configs/registration-emails?${parameters}`);
    const data = result.data || {};
    const pagination = data.pagination || {};
    for (const row of document.querySelectorAll("[data-allowlist-entry]")) row.remove();
    for (const entry of data.items || []) appendAllowlistEntry(entry, false);
    updateAllowlistEmpty();
    allowlistPaging.query = query;
    allowlistPaging.page = Number(pagination.page || page);
    allowlistPaging.pages = Number(pagination.pages || 0);
    previous.disabled = allowlistPaging.page <= 1;
    next.disabled = allowlistPaging.pages === 0 || allowlistPaging.page >= allowlistPaging.pages;
    if (status) {
      status.textContent = allowlistPaging.pages
        ? `Page ${allowlistPaging.page} of ${allowlistPaging.pages}`
        : "No matches";
    }
  } catch (error) {
    showToast(error.message || "The allowlist could not be searched.", "error", 5500);
    if (status) status.textContent = "Load failed";
  }
}

document.querySelector("[data-allowlist-search]")?.addEventListener("submit", event => {
  event.preventDefault();
  loadAllowlistPage(1);
});
document.querySelector("[data-allowlist-previous]")?.addEventListener("click", () => {
  if (allowlistPaging.page > 1) loadAllowlistPage(allowlistPaging.page - 1);
});
document.querySelector("[data-allowlist-next]")?.addEventListener("click", () => {
  if (allowlistPaging.pages === null) {
    loadAllowlistPage(1);
  } else if (allowlistPaging.page < allowlistPaging.pages) {
    loadAllowlistPage(allowlistPaging.page + 1);
  }
});

document.querySelector("[data-allowlist-add]")?.addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const button = form.querySelector('button[type="submit"]');
  setBusy(button, true, "Adding…");
  try {
    const result = await apiRequest("/api/v1/configs/registration-emails", {
      method: "POST",
      body: { email: form.elements.email.value.trim() },
    });
    if (allowlistPaging.query || allowlistPaging.pages !== null) {
      updateAllowlistCount(1);
      await loadAllowlistPage(allowlistPaging.page);
    } else {
      appendAllowlistEntry(result.data);
    }
    form.reset();
    showToast("Email address added to the registration allowlist.");
  } catch (error) {
    showToast(error.message || "The email address could not be added.", "error", 5500);
  } finally {
    setBusy(button, false);
  }
});

const allowlistFile = document.querySelector("[data-allowlist-file]");
allowlistFile?.addEventListener("change", () => {
  const label = document.querySelector("[data-allowlist-file-name]");
  if (label) label.textContent = allowlistFile.files?.[0]?.name || "No file selected";
});

document.querySelector("[data-allowlist-import]")?.addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const button = form.querySelector('button[type="submit"]');
  setBusy(button, true, "Importing…");
  try {
    const body = new FormData();
    body.append("file", form.elements.file.files[0]);
    const result = await apiRequest("/api/v1/configs/registration-emails/import", { method: "POST", body });
    showToast(`${result.data?.added || 0} address${result.data?.added === 1 ? "" : "es"} imported.`);
    window.setTimeout(() => window.location.reload(), 500);
  } catch (error) {
    showToast(error.message || "The allowlist CSV could not be imported.", "error", 5500);
  } finally {
    setBusy(button, false);
  }
});

document.querySelector("[data-registration-allowlist]")?.addEventListener("click", async event => {
  const button = event.target.closest("[data-allowlist-delete]");
  if (!button || button.disabled || !window.confirm("Remove this email from the registration allowlist?")) return;
  setBusy(button, true, "Removing…");
  try {
    await apiRequest(`/api/v1/configs/registration-emails/${encodeURIComponent(button.dataset.allowlistDelete)}`, { method: "DELETE" });
    button.closest("[data-allowlist-entry]")?.remove();
    updateAllowlistCount(-1);
    updateAllowlistEmpty();
    showToast("Email address removed from the registration allowlist.");
  } catch (error) {
    showToast(error.message || "The email address could not be removed.", "error", 5500);
    setBusy(button, false);
  }
});

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

function finishSessionRevocation(data, message) {
  showToast(message);
  const signedOut = data?.current_session_revoked === true;
  window.setTimeout(() => {
    if (signedOut) {
      window.location.assign("/login");
    } else {
      window.location.reload();
    }
  }, 450);
}

for (const button of document.querySelectorAll("[data-revoke-session]")) {
  button.addEventListener("click", async () => {
    const current = button.dataset.currentSession === "true";
    const warning = current
      ? "Terminate your current browser session? You will be signed out of administration."
      : "Terminate this browser session? The user will need to sign in again on that browser.";
    if (!window.confirm(warning)) return;
    setBusy(button, true, "Terminating…");
    try {
      const result = await apiRequest(
        `/api/v1/sessions/${encodeURIComponent(button.dataset.revokeSession)}/revoke`,
        { method: "POST" },
      );
      const count = Number(result.data?.revoked || 0);
      finishSessionRevocation(
        result.data,
        count ? "Session terminated." : "The session was already terminated.",
      );
    } catch (error) {
      showToast(error.message || "The session could not be terminated.", "error", 5500);
      setBusy(button, false);
    }
  });
}

for (const button of document.querySelectorAll("[data-revoke-user-sessions]")) {
  button.addEventListener("click", async () => {
    if (!window.confirm(
      "Terminate every browser session for this user? API tokens are not affected.",
    )) return;
    setBusy(button, true, "Terminating…");
    try {
      const result = await apiRequest(
        `/api/v1/sessions/users/${encodeURIComponent(button.dataset.revokeUserSessions)}/revoke`,
        { method: "POST" },
      );
      const count = Number(result.data?.revoked || 0);
      finishSessionRevocation(
        result.data,
        `${count} browser session${count === 1 ? "" : "s"} terminated.`,
      );
    } catch (error) {
      showToast(error.message || "The user's sessions could not be terminated.", "error", 5500);
      setBusy(button, false);
    }
  });
}

for (const button of document.querySelectorAll("[data-revoke-all-sessions]")) {
  button.addEventListener("click", async () => {
    if (!window.confirm(
      "Terminate every browser session for every user? This includes your current administration session, so you will be signed out. API tokens are not affected.",
    )) return;
    setBusy(button, true, "Terminating…");
    try {
      const result = await apiRequest("/api/v1/sessions/revoke", { method: "POST" });
      const count = Number(result.data?.revoked || 0);
      finishSessionRevocation(
        result.data,
        `${count} browser session${count === 1 ? "" : "s"} terminated across all users.`,
      );
    } catch (error) {
      showToast(error.message || "User sessions could not be terminated.", "error", 5500);
      setBusy(button, false);
    }
  });
}

const userForm = document.querySelector("[data-user-form]");
if (userForm) {
  const role = userForm.elements.type;
  const hidden = userForm.elements.hidden;
  const hiddenLabel = hidden?.closest(".admin-switch")?.querySelector("strong");
  hidden?.addEventListener("change", () => {
    if (hiddenLabel) hiddenLabel.textContent = hidden.checked ? "Hidden" : "Visible";
  });

  userForm.addEventListener("submit", async event => {
    event.preventDefault();
    if (!userForm.reportValidity()) return;
    const roleChanged = role.value !== userForm.dataset.initialRole;
    if (roleChanged && !window.confirm(
      "Changing this role revokes the user’s browser sessions and API tokens. Save this change?",
    )) return;
    const button = userForm.querySelector('button[type="submit"]');
    setBusy(button, true);
    try {
      await apiRequest(`/api/v1/users/${encodeURIComponent(userForm.dataset.userId)}`, {
        method: "PATCH",
        body: { type: role.value, hidden: hidden.checked },
      });
      showToast("User access settings saved.");
      const currentAdminChanged = roleChanged && userForm.dataset.currentUser === "true";
      window.setTimeout(() => {
        window.location.assign(currentAdminChanged ? "/login" : "/admin/users");
      }, 400);
    } catch (error) {
      showToast(error.message || "The user could not be updated.", "error", 5500);
      setBusy(button, false);
    }
  });
}
