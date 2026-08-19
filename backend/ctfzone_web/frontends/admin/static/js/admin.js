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
  return undefined;
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

const categoryLogoKeys = new Set([
  "web", "pwn", "crypto", "rev", "misc", "coding", "forensics",
]);

function normalizeCategoryLogoKey(value) {
  const key = typeof value === "string" ? value.trim().toLocaleLowerCase() : "";
  return categoryLogoKeys.has(key) ? key : "";
}

function normalizeCategoryLogoColor(value) {
  const color = typeof value === "string" ? value.trim().toLocaleLowerCase() : "";
  return /^#[0-9a-f]{6}$/.test(color) ? color : "#34689c";
}

function syncCategoryFallback(container, logoKey, name, logoColor = "#34689c") {
  const fallback = container?.querySelector("[data-category-icon-fallback]");
  if (!fallback) return null;
  const key = normalizeCategoryLogoKey(logoKey);
  const nameNode = fallback.querySelector("[data-category-preview-name]");
  if (nameNode) {
    nameNode.textContent = name;
    nameNode.hidden = Boolean(key);
  }
  for (const logo of fallback.querySelectorAll("[data-category-builtin-logo]")) {
    logo.hidden = logo.dataset.categoryBuiltinLogo !== key;
    logo.querySelector("svg")?.setAttribute("stroke", normalizeCategoryLogoColor(logoColor));
  }
  return fallback;
}

function prepareCategoryImage(image, fallback, source = image?.getAttribute("src") || "") {
  const marker = image?.closest(".category-image-marker");
  if (!image) return;
  image.hidden = true;
  if (fallback) fallback.hidden = false;
  marker?.classList.remove("icon-loaded");
  image.onload = () => {
    if (image.naturalWidth < 1 || image.naturalHeight < 1) return;
    image.hidden = false;
    if (fallback) fallback.hidden = true;
    marker?.classList.add("icon-loaded");
  };
  image.onerror = () => {
    image.hidden = true;
    if (fallback) fallback.hidden = false;
    marker?.classList.remove("icon-loaded");
  };
  if (!source) {
    image.removeAttribute("src");
    return;
  }
  if (image.getAttribute("src") !== source) image.src = source;
  else if (image.complete && image.naturalWidth) image.onload();
}

for (const image of document.querySelectorAll("[data-category-icon-image]")) {
  prepareCategoryImage(
    image,
    image.closest(".category-image-marker")?.querySelector("[data-category-icon-fallback]"),
  );
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
  const staticValueField = challengeForm.querySelector("[data-static-value]");
  const syncChallengeType = () => {
    const dynamic = typeField?.value === "dynamic";
    dynamicFields?.classList.toggle("visible", dynamic);
    for (const input of dynamicFields?.querySelectorAll("input, select") || []) input.disabled = !dynamic;
    if (staticValueField) staticValueField.hidden = dynamic;
    if (challengeForm.elements.value) challengeForm.elements.value.disabled = dynamic;
  };
  typeField?.addEventListener("change", syncChallengeType);
  syncChallengeType();

  const categoryDialog = document.querySelector("[data-category-dialog]");
  const categoryDialogForm = categoryDialog?.querySelector("[data-category-dialog-form]");
  const categorySelect = challengeForm.querySelector("[data-category-select]");
  const categoryHelp = challengeForm.querySelector("[data-category-help]");
  const categoryError = categoryDialog?.querySelector("[data-category-dialog-error]");
  const categorySelectionPreview = challengeForm.querySelector("[data-category-selection-preview]");
  const categorySelectionImage = challengeForm.querySelector("[data-category-selection-image]");
  const categorySelectionFallback = challengeForm.querySelector("[data-category-selection-preview] [data-category-icon-fallback]");
  const categoryCreateHeaders = new Map();
  let categoryReturnFocus = null;

  const syncCategorySelectionPreview = () => {
    const option = categorySelect?.selectedOptions?.[0];
    const hasCategory = Boolean(option?.value);
    if (categorySelectionPreview) categorySelectionPreview.hidden = !hasCategory;
    if (!hasCategory) return;
    categorySelectionPreview?.setAttribute(
      "aria-label",
      `Player marker for ${option.textContent.trim()}`,
    );
    syncCategoryFallback(
      categorySelectionPreview,
      option.dataset.categoryLogoKey,
      option.textContent.trim(),
      option.dataset.categoryLogoColor,
    );
    prepareCategoryImage(
      categorySelectionImage,
      categorySelectionFallback,
      option.dataset.categoryIconUrl || "",
    );
  };
  categorySelect?.addEventListener("change", syncCategorySelectionPreview);
  syncCategorySelectionPreview();

  const closeCategoryDialog = () => {
    if (!categoryDialog) return;
    if (typeof categoryDialog.close === "function" && categoryDialog.open) categoryDialog.close();
    else categoryDialog.removeAttribute("open");
    categoryReturnFocus?.focus({ preventScroll: true });
    categoryReturnFocus = null;
  };

  challengeForm.querySelector("[data-open-category-dialog]")?.addEventListener("click", event => {
    if (!categoryDialog || !categoryDialogForm) return;
    categoryReturnFocus = event.currentTarget;
    categoryDialogForm.reset();
    if (categoryError) categoryError.textContent = "";
    if (typeof categoryDialog.showModal === "function") categoryDialog.showModal();
    else categoryDialog.setAttribute("open", "");
    window.requestAnimationFrame(() => categoryDialogForm.elements.category_name?.focus());
  });
  for (const button of categoryDialog?.querySelectorAll("[data-close-category-dialog]") || []) {
    button.addEventListener("click", closeCategoryDialog);
  }
  categoryDialog?.addEventListener("click", event => {
    if (event.target === categoryDialog) closeCategoryDialog();
  });
  categoryDialog?.addEventListener("close", () => {
    categoryReturnFocus?.focus({ preventScroll: true });
    categoryReturnFocus = null;
  });
  categoryDialogForm?.addEventListener("submit", async event => {
    event.preventDefault();
    if (!categoryDialogForm.reportValidity()) return;
    const submit = categoryDialogForm.querySelector('button[type="submit"]');
    setBusy(submit, true, "Creating…");
    if (categoryError) categoryError.textContent = "";
    try {
      const categoryName = categoryDialogForm.elements.category_name.value.trim();
      const categoryKey = categoryName.toLocaleLowerCase();
      if (!categoryCreateHeaders.has(categoryKey)) {
        categoryCreateHeaders.set(categoryKey, idempotencyHeaders());
      }
      const result = await apiRequest("/api/v1/admin/challenge-categories", {
        method: "POST",
        headers: categoryCreateHeaders.get(categoryKey),
        body: { name: categoryName },
      });
      const category = result.data;
      if (!Number.isSafeInteger(Number(category?.id)) || !category?.name) {
        throw new Error("The category service returned an invalid category.");
      }
      let option = Array.from(categorySelect?.options || [])
        .find(candidate => candidate.value === String(category.id));
      if (!option && categorySelect) {
        option = new Option(category.name, String(category.id));
        categorySelect.add(option);
      }
      if (option && categorySelect) {
        option.textContent = category.name;
        option.dataset.categoryIconUrl = "";
        option.dataset.categoryLogoKey = normalizeCategoryLogoKey(category.logo_key);
        option.dataset.categoryLogoColor = normalizeCategoryLogoColor(category.logo_color);
        categorySelect.value = String(category.id);
        categorySelect.dispatchEvent(new Event("change", { bubbles: true }));
      }
      if (categoryHelp) categoryHelp.textContent = "Category created and selected. It is now available to other challenges.";
      setBusy(submit, false);
      closeCategoryDialog();
      showToast(`Category “${category.name}” created.`);
    } catch (error) {
      if (categoryError) categoryError.textContent = error.message || "The category could not be created.";
      setBusy(submit, false);
    }
  });

  const wizard = challengeForm.querySelector("[data-wizard-step]") ? challengeForm : null;
  const challengeCreateStorageKey = "ctfzone.admin.challenge-create-idempotency";
  let challengeCreateHeaders;
  if (wizard) {
    let key;
    try {
      key = window.sessionStorage.getItem(challengeCreateStorageKey);
      if (!key) {
        key = idempotencyHeaders()["idempotency-key"];
        window.sessionStorage.setItem(challengeCreateStorageKey, key);
      }
    } catch (_error) {
      key = idempotencyHeaders()["idempotency-key"];
    }
    challengeCreateHeaders = { "idempotency-key": key };
  }
  const randomTokenPlaceholder = "{{RANDOM_TOKEN}}";
  const flagByteLength = value => new TextEncoder().encode(value).length;
  const exposureValue = () => challengeForm.elements.exposure?.value || "";
  const flagTypeValue = () => challengeForm.elements.flag_type?.value || "static";
  const randomTokenCountIn = value => value.split(randomTokenPlaceholder).length - 1;
  const randomTokenCount = () => {
    const content = challengeForm.elements.flag_content?.value || "";
    return randomTokenCountIn(content);
  };
  const hasUnsupportedGeneratedPlaceholder = value => {
    const withoutRandomToken = value.split(randomTokenPlaceholder).join("");
    return withoutRandomToken.includes("{{") || withoutRandomToken.includes("}}");
  };
  const leetScope = template => {
    const tokenStart = template.indexOf(randomTokenPlaceholder);
    const tokenEnd = tokenStart < 0 ? -1 : tokenStart + randomTokenPlaceholder.length;
    const isTokenIndex = index => tokenStart >= 0 && index >= tokenStart && index < tokenEnd;
    let open = -1;
    let close = -1;
    for (let index = 0; index < template.length; index += 1) {
      if (template[index] === "{" && !isTokenIndex(index)) {
        open = index;
        break;
      }
    }
    for (let index = template.length - 1; index >= 0; index -= 1) {
      if (template[index] === "}" && !isTokenIndex(index)) {
        close = index;
        break;
      }
    }
    return open >= 0 && open < close
      ? { start: open + 1, end: close }
      : { start: 0, end: template.length };
  };
  const leetEligibleCount = () => {
    const template = challengeForm.elements.flag_content?.value || "";
    const scope = leetScope(template);
    let eligible = 0;
    for (let cursor = 0; cursor < template.length;) {
      if (template.startsWith(randomTokenPlaceholder, cursor)) {
        cursor += randomTokenPlaceholder.length;
        continue;
      }
      const character = String.fromCodePoint(template.codePointAt(cursor));
      if (cursor >= scope.start && cursor < scope.end && /[aeiost]/i.test(character)) eligible += 1;
      cursor += character.length;
    }
    return eligible;
  };
  const leetSample = template => {
    const scope = leetScope(template);
    const leetMap = { a: "4", e: "3", i: "1", o: "0", s: "5", t: "7" };
    let rendered = "";
    for (let cursor = 0; cursor < template.length;) {
      if (template.startsWith(randomTokenPlaceholder, cursor)) {
        rendered += "<uuid>";
        cursor += randomTokenPlaceholder.length;
        continue;
      }
      const character = String.fromCodePoint(template.codePointAt(cursor));
      const replacement = cursor >= scope.start && cursor < scope.end
        ? leetMap[character.toLowerCase()]
        : undefined;
      rendered += replacement || character;
      cursor += character.length;
    }
    return rendered;
  };

  const syncPersonalization = () => {
    if (!wizard) return;
    const privateExact = exposureValue() === "private" && flagTypeValue() === "static";
    const options = challengeForm.querySelector("[data-private-flag-options]");
    if (options) options.hidden = !privateExact;
    const contentInput = challengeForm.elements.flag_content;
    const count = randomTokenCount();
    const renderedBytes = flagByteLength(contentInput?.value || "")
      + (count === 1 ? 36 - flagByteLength(randomTokenPlaceholder) : 0);
    const leet = Boolean(challengeForm.elements.leet_variation?.checked);
    const personalized = privateExact && (count === 1 || leet);
    const unsupportedPlaceholder = personalized
      && hasUnsupportedGeneratedPlaceholder(challengeForm.elements.flag_content?.value || "");
    const accept = challengeForm.elements.accept_other_users;
    if (accept) {
      accept.disabled = !personalized;
      if (!personalized) accept.checked = false;
    }
    const tokenStatus = challengeForm.querySelector("[data-random-token-status]");
    if (tokenStatus) {
      tokenStatus.textContent = count === 0 ? "No random token" : count === 1 ? "UUID token detected" : "Too many tokens";
      tokenStatus.classList.toggle("good", count === 1);
      tokenStatus.classList.toggle("bad", count > 1);
    }
    const leetInput = challengeForm.elements.leet_variation;
    if (leetInput) leetInput.disabled = !privateExact;
    contentInput?.setCustomValidity(
      flagByteLength(contentInput.value) > 512
        ? "The flag template must be at most 512 UTF-8 bytes."
        : count > 1
        ? "Use {{RANDOM_TOKEN}} at most once."
        : privateExact && count === 1 && renderedBytes > 512
          ? "The generated flag must be at most 512 UTF-8 bytes after UUID replacement."
        : exposureValue() === "public" && count > 0
          ? "Random tokens are available only for private challenges."
          : unsupportedPlaceholder
            ? "Generated flags support only the exact {{RANDOM_TOKEN}} placeholder."
            : "",
    );
    const eligible = leetEligibleCount();
    const sample = leetSample(contentInput?.value || "flag{this_is_a_flag}");
    leetInput?.setCustomValidity(
      privateExact && leet && eligible === 0
        ? "Leet variation requires at least one a, e, i, o, s, or t in the literal template."
        : privateExact && leet && eligible > 62
          ? "Leet variation supports at most 62 eligible letters."
          : "",
    );
    const caseSetting = challengeForm.querySelector("[data-case-sensitive-setting]");
    if (caseSetting) caseSetting.hidden = personalized;
    const preview = challengeForm.querySelector("[data-flag-example]");
    if (!preview || !privateExact) return;
    preview.classList.remove("good", "warning");
    if (leet && eligible === 0) {
      preview.textContent = "No leet-eligible letters found. Add at least one a, e, i, o, s, or t to the literal template.";
      preview.classList.add("warning");
    } else if (leet && eligible > 62) {
      preview.textContent = `${eligible} leet-eligible letters found; reduce the template to at most 62 before continuing.`;
      preview.classList.add("warning");
    } else if (leet && count === 0) {
      const capacity = eligible <= 52
        ? ((1n << BigInt(eligible)) - 1n).toLocaleString()
        : "more than 4 quadrillion";
      preview.textContent = `Example: ${sample}. Finite capacity: ${capacity} unique non-original leet variation${capacity === "1" ? "" : "s"}. Activation is refused after exhaustion; assignments persist from first activation.`;
      preview.classList.add("warning");
    } else if (leet && count === 1) {
      preview.textContent = `Example: ${sample}. ${eligible} leet-eligible position${eligible === 1 ? "" : "s"}; the UUIDv4 token guarantees uniqueness. Assignments persist from first activation.`;
      preview.classList.add("good");
    } else if (count === 1) {
      preview.textContent = "A UUIDv4 will replace the token for each participant. The generated assignment persists from first activation.";
      preview.classList.add("good");
    } else {
      preview.textContent = "This is one shared exact flag. Add {{RANDOM_TOKEN}} or enable leet variation to personalize it.";
    }
    const reviewLabel = personalized
      ? [count === 1 ? "Random token" : "", leet ? "Leet variation" : ""].filter(Boolean).join(" + ")
      : "Exact match";
    for (const review of challengeForm.querySelectorAll("[data-review-flag]")) review.textContent = reviewLabel;
  };

  const syncFlagType = () => {
    if (!wizard) return;
    const regex = flagTypeValue() === "regex";
    const staticFields = challengeForm.querySelector("[data-static-flag-fields]");
    const regexFields = challengeForm.querySelector("[data-regex-flag-fields]");
    if (staticFields) staticFields.hidden = regex;
    if (regexFields) regexFields.hidden = !regex;
    if (challengeForm.elements.flag_content) challengeForm.elements.flag_content.disabled = regex;
    if (challengeForm.elements.case_sensitive) challengeForm.elements.case_sensitive.disabled = regex;
    if (challengeForm.elements.leet_variation) challengeForm.elements.leet_variation.disabled = regex;
    const regexInput = challengeForm.elements.flag_regex_content;
    if (regexInput) regexInput.disabled = !regex;
    regexInput?.setCustomValidity(
      regex && flagByteLength(regexInput.value) > 512
        ? "The regular expression must be at most 512 UTF-8 bytes."
        : regex && randomTokenCountIn(regexInput.value) > 0
          ? "Random tokens are not available for regular expression flags."
          : "",
    );
    if (regex && challengeForm.elements.accept_other_users) {
      challengeForm.elements.accept_other_users.checked = false;
      challengeForm.elements.accept_other_users.disabled = true;
    }
    for (const review of challengeForm.querySelectorAll("[data-review-flag]")) {
      review.textContent = regex ? "Regular expression" : "Exact match";
    }
    syncPersonalization();
  };

  const syncGlobalRuntimeGate = ({ enforce = false } = {}) => {
    if (!wizard) return;
    const runtimeFields = challengeForm.querySelector("[data-challenge-runtime-fields]");
    const gateAlreadyEnabled = runtimeFields?.dataset.globalGateEnabled === "true";
    const enableGate = challengeForm.elements.enable_global_gate;
    const requestedState = challengeForm.elements.state?.value || "hidden";
    const gateReady = gateAlreadyEnabled || Boolean(enableGate?.checked);
    challengeForm.elements.state?.setCustomValidity("");
    enableGate?.setCustomValidity(
      enforce && exposureValue() === "private" && requestedState !== "hidden" && !gateReady
        ? "Enable private challenge launches globally, or save this challenge as a hidden draft."
        : "",
    );
    enableGate?.closest(".challenge-global-gate")?.classList.toggle("confirmed", Boolean(enableGate.checked));
  };

  const syncExposure = () => {
    if (!wizard) return;
    const exposure = exposureValue();
    const publicExplanation = challengeForm.querySelector("[data-public-explanation]");
    const privateExplanation = challengeForm.querySelector("[data-private-explanation]");
    const publicConnectionNote = challengeForm.querySelector("[data-public-connection-note]");
    const privateConnectionNote = challengeForm.querySelector("[data-private-connection-note]");
    const runtimeSettings = challengeForm.querySelector("[data-challenge-runtime-fields]");
    if (publicExplanation) publicExplanation.hidden = exposure !== "public";
    if (privateExplanation) privateExplanation.hidden = exposure !== "private";
    if (publicConnectionNote) publicConnectionNote.hidden = exposure !== "public";
    if (privateConnectionNote) privateConnectionNote.hidden = exposure !== "private";
    if (runtimeSettings) runtimeSettings.hidden = exposure !== "private";
    for (const control of runtimeSettings?.querySelectorAll("input, select, textarea") || []) {
      control.disabled = exposure !== "private";
    }
    for (const review of challengeForm.querySelectorAll("[data-review-exposure]")) {
      review.textContent = exposure === "private" ? "Private instance" : exposure === "public" ? "Public challenge" : "—";
    }
    const summary = challengeForm.querySelector("[data-submit-summary]");
    if (summary) summary.textContent = exposure === "private" ? "Jeopardy · private instance" : "Jeopardy · public challenge";
    syncFlagType();
    syncGlobalRuntimeGate();
  };

  if (wizard) {
    const panels = Array.from(challengeForm.querySelectorAll("[data-wizard-step]"));
    const triggers = Array.from(challengeForm.querySelectorAll("[data-wizard-step-trigger]"));
    const announcement = challengeForm.querySelector("[data-wizard-announcement]");
    const stepNames = ["Challenge type", "Availability", "Details", "Flag", "Connection"];
    let currentStep = 1;
    let furthestStep = 1;

    const setCrossFieldValidity = step => {
      if (step === 4) syncPersonalization();
      const minimum = challengeForm.elements.minimum;
      minimum?.setCustomValidity(
        step === 3 && typeField?.value === "dynamic" && asNumber(challengeForm, "minimum", 100) > asNumber(challengeForm, "initial", 500)
          ? "Minimum score cannot exceed the initial score."
          : "",
      );
      if (step !== 5) return;
      syncGlobalRuntimeGate({ enforce: true });
      const image = challengeForm.elements.image_digest;
      if (exposureValue() === "private" && image) {
        const validDigest = /^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$/.test(image.value.trim());
        image.setCustomValidity(validDigest ? "" : "Enter an immutable image reference ending in @sha256: and 64 lowercase hexadecimal characters.");
      } else image?.setCustomValidity("");
      const maximumTtl = challengeForm.elements.maximum_ttl_minutes;
      const defaultTtl = asNumber(challengeForm, "default_ttl_minutes", 30);
      maximumTtl?.setCustomValidity(
        exposureValue() === "private" && asNumber(challengeForm, "maximum_ttl_minutes", 60) < defaultTtl
          ? "Maximum lifetime must be at least the default lifetime."
          : "",
      );
    };

    const validateStep = step => {
      setCrossFieldValidity(step);
      const panel = panels.find(candidate => Number(candidate.dataset.wizardStep) === step);
      const invalid = Array.from(panel?.querySelectorAll("input, select, textarea") || [])
        .find(control => !control.disabled && !control.checkValidity());
      if (!invalid) return true;
      invalid.reportValidity();
      invalid.focus({ preventScroll: true });
      invalid.scrollIntoView({ behavior: reducedMotionQuery.matches ? "auto" : "smooth", block: "center" });
      return false;
    };

    const showStep = (step, { focus = true } = {}) => {
      currentStep = Math.min(panels.length, Math.max(1, step));
      furthestStep = Math.max(furthestStep, currentStep);
      for (const panel of panels) panel.hidden = Number(panel.dataset.wizardStep) !== currentStep;
      for (const trigger of triggers) {
        const triggerStep = Number(trigger.dataset.wizardStepTrigger);
        const item = trigger.closest("[data-wizard-progress-item]");
        const active = triggerStep === currentStep;
        trigger.disabled = triggerStep > furthestStep;
        item?.classList.toggle("active", active);
        item?.classList.toggle("complete", triggerStep < currentStep);
        if (active) trigger.setAttribute("aria-current", "step");
        else trigger.removeAttribute("aria-current");
      }
      if (announcement) announcement.textContent = `Step ${currentStep} of ${panels.length}: ${stepNames[currentStep - 1]}`;
      const title = panels.find(panel => Number(panel.dataset.wizardStep) === currentStep)?.querySelector("h2");
      if (focus) {
        title?.focus({ preventScroll: true });
        challengeForm.querySelector("[data-wizard-progress-item].active")?.scrollIntoView({ behavior: reducedMotionQuery.matches ? "auto" : "smooth", block: "nearest", inline: "center" });
      }
    };

    for (const trigger of triggers) {
      trigger.addEventListener("click", () => {
        const target = Number(trigger.dataset.wizardStepTrigger);
        if (target > currentStep) {
          for (let step = currentStep; step < target; step += 1) {
            showStep(step, { focus: false });
            if (!validateStep(step)) return;
          }
        }
        showStep(target);
      });
    }
    for (const panel of panels) {
      panel.querySelector("[data-wizard-next]")?.addEventListener("click", () => {
        if (validateStep(currentStep)) showStep(currentStep + 1);
      });
      panel.querySelector("[data-wizard-back]")?.addEventListener("click", () => showStep(currentStep - 1));
    }
    for (const radio of challengeForm.querySelectorAll('input[name="exposure"]')) radio.addEventListener("change", syncExposure);
    for (const radio of challengeForm.querySelectorAll('input[name="flag_type"]')) radio.addEventListener("change", syncFlagType);
    challengeForm.elements.flag_content?.addEventListener("input", syncPersonalization);
    challengeForm.elements.flag_regex_content?.addEventListener("input", syncFlagType);
    challengeForm.elements.leet_variation?.addEventListener("change", syncPersonalization);
    challengeForm.elements.image_digest?.addEventListener("input", () => challengeForm.elements.image_digest.setCustomValidity(""));
    challengeForm.elements.maximum_ttl_minutes?.addEventListener("input", () => challengeForm.elements.maximum_ttl_minutes.setCustomValidity(""));
    challengeForm.elements.minimum?.addEventListener("input", () => challengeForm.elements.minimum.setCustomValidity(""));
    challengeForm.elements.state?.addEventListener("change", syncGlobalRuntimeGate);
    challengeForm.elements.enable_global_gate?.addEventListener("change", syncGlobalRuntimeGate);
    syncExposure();
    showStep(1, { focus: false });
  }

  const privateEditGate = challengeForm.querySelector("[data-private-edit-gate]");
  const syncPrivateEditGate = () => {
    if (!privateEditGate) return;
    const gateAlreadyEnabled = privateEditGate.dataset.globalGateEnabled === "true";
    const enableGate = challengeForm.elements.enable_global_gate;
    const requestedState = challengeForm.elements.state?.value || "hidden";
    const gateReady = gateAlreadyEnabled || Boolean(enableGate?.checked);
    challengeForm.elements.state?.setCustomValidity(
      requestedState !== "hidden" && !gateReady
        ? "Enable private challenge launches globally, or keep this challenge hidden."
        : "",
    );
    enableGate?.closest(".challenge-global-gate")?.classList.toggle("confirmed", Boolean(enableGate.checked));
  };
  if (privateEditGate) {
    challengeForm.elements.state?.addEventListener("change", syncPrivateEditGate);
    challengeForm.elements.enable_global_gate?.addEventListener("change", syncPrivateEditGate);
    syncPrivateEditGate();
  }

  const commonChallengePayload = () => {
    const dynamic = typeField?.value === "dynamic";
    const payload = {
      name: challengeForm.elements.name.value.trim(),
      category_id: Number(challengeForm.elements.category_id.value),
      description: challengeForm.elements.description.value,
      attribution: challengeForm.elements.attribution?.value.trim() || null,
      connection_info: challengeForm.elements.connection_info?.value.trim() || null,
      type: typeField?.value || "standard",
      function: dynamic ? challengeForm.elements.function.value : "static",
      value: dynamic ? asNumber(challengeForm, "initial", 500) : asNumber(challengeForm, "value", 500),
      state: challengeForm.elements.state.value,
      max_attempts: asNumber(challengeForm, "max_attempts", 0),
      position: asNumber(challengeForm, "position", 0),
    };
    if (dynamic) {
      payload.initial = asNumber(challengeForm, "initial", 500);
      payload.minimum = asNumber(challengeForm, "minimum", 100);
      payload.decay = asNumber(challengeForm, "decay", 50);
    }
    return payload;
  };

  const createFlagPayload = () => {
    const regex = flagTypeValue() === "regex";
    const leet = Boolean(challengeForm.elements.leet_variation?.checked);
    const generated = exposureValue() === "private" && !regex && (randomTokenCount() === 1 || leet);
    return {
      type: regex ? "regex" : generated ? "generated" : "static",
      content: (regex ? challengeForm.elements.flag_regex_content.value : challengeForm.elements.flag_content.value).trim(),
      data: regex
        ? {}
        : generated
          ? { leet_variation: leet, accept_other_users: Boolean(challengeForm.elements.accept_other_users?.checked) }
          : { case_sensitive: Boolean(challengeForm.elements.case_sensitive?.checked) },
    };
  };

  const optionalMiB = name => {
    const value = challengeForm.elements[name]?.value?.trim();
    return value ? Number(value) * 1024 * 1024 : null;
  };
  const createRuntimePayload = () => ({
    runtime_mode: "managed",
    enabled: true,
    image_digest: challengeForm.elements.image_digest.value.trim(),
    protocol: challengeForm.elements.runtime_protocol.value,
    container_port: asNumber(challengeForm, "container_port"),
    default_ttl_seconds: asNumber(challengeForm, "default_ttl_minutes", 30) * 60,
    maximum_ttl_seconds: asNumber(challengeForm, "maximum_ttl_minutes", 60) * 60,
    allow_extension: Boolean(challengeForm.elements.allow_extension.checked),
    maximum_extensions: asNumber(challengeForm, "maximum_extensions", 2),
    cpu_limit: challengeForm.elements.cpu_limit.value.trim() || null,
    memory_limit_bytes: optionalMiB("memory_limit_mib"),
    pid_limit: challengeForm.elements.pid_limit.value.trim() ? asNumber(challengeForm, "pid_limit") : null,
    storage_limit_bytes: optionalMiB("storage_limit_mib"),
    healthcheck: {},
    remote_pool: challengeForm.elements.remote_pool.value.trim() || null,
    enable_global_gate: Boolean(challengeForm.elements.enable_global_gate?.checked),
  });

  challengeForm.addEventListener("submit", async event => {
    event.preventDefault();
    syncPrivateEditGate();
    if (wizard) {
      syncPersonalization();
      syncFlagType();
      syncGlobalRuntimeGate({ enforce: true });
      const image = challengeForm.elements.image_digest;
      if (exposureValue() === "private" && image) {
        const validDigest = /^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$/.test(image.value.trim());
        image.setCustomValidity(validDigest ? "" : "Enter an immutable image reference ending in @sha256: and 64 lowercase hexadecimal characters.");
      }
      const maximumTtl = challengeForm.elements.maximum_ttl_minutes;
      maximumTtl?.setCustomValidity(
        exposureValue() === "private"
          && asNumber(challengeForm, "maximum_ttl_minutes", 60) < asNumber(challengeForm, "default_ttl_minutes", 30)
          ? "Maximum lifetime must be at least the default lifetime."
          : "",
      );
      const minimum = challengeForm.elements.minimum;
      minimum?.setCustomValidity(
        typeField?.value === "dynamic"
          && asNumber(challengeForm, "minimum", 100) > asNumber(challengeForm, "initial", 500)
          ? "Minimum score cannot exceed the initial score."
          : "",
      );
    }
    if (!challengeForm.reportValidity()) return;
    const submit = challengeForm.querySelector('button[type="submit"]');
    const fileInput = challengeForm.querySelector("[data-challenge-files]");
    const uploadStatus = challengeForm.querySelector("[data-upload-status]");
    const selectedFiles = Array.from(fileInput?.files || []);
    let stagedDesiredState = null;
    setBusy(submit, true);

    try {
      const mode = challengeForm.dataset.mode;
      const payload = commonChallengePayload();
      if (mode === "create") {
        payload.logic = "any";
        payload.challenge_type = challengeForm.elements.challenge_type.value;
        payload.exposure = exposureValue();
        payload.flag = createFlagPayload();
        if (selectedFiles.length && payload.state !== "hidden") {
          stagedDesiredState = payload.state;
          payload.state = "hidden";
        }
        if (exposureValue() === "private") {
          payload.runtime = createRuntimePayload();
        }
      } else {
        if (challengeForm.elements.enable_global_gate?.checked) {
          payload.enable_global_gate = true;
        }
      }
      const path = mode === "create"
        ? "/api/v1/challenges"
        : `/api/v1/challenges/${challengeForm.dataset.challengeId}`;
      const result = await apiRequest(path, {
        method: mode === "create" ? "POST" : "PATCH",
        headers: mode === "create" ? challengeCreateHeaders : undefined,
        body: payload,
      });
      if (mode === "create") {
        try {
          window.sessionStorage.removeItem(challengeCreateStorageKey);
        } catch (_error) {
          // Idempotency remains server-enforced when session storage is unavailable.
        }
      }
      const challengeId = result.data?.id || challengeForm.dataset.challengeId;
      let uploadedFiles = 0;
      try {
        uploadedFiles = await uploadChallengeFiles(fileInput, uploadStatus, challengeId);
      } catch (error) {
        if (uploadStatus) uploadStatus.textContent = `Upload stopped: ${error.message}`;
        showToast(
          `Challenge ${mode === "create" ? "created" : "updated"}, but its files were not all attached: ${error.message}${stagedDesiredState ? " It remains hidden until you retry." : ""}`,
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
      if (mode === "create" && stagedDesiredState) {
        try {
          await apiRequest(`/api/v1/challenges/${challengeId}`, {
            method: "PATCH",
            body: { state: stagedDesiredState },
          });
        } catch (error) {
          showToast(`Challenge and files were saved, but publication failed: ${error.message}. The challenge remains hidden.`, "warning", 7000);
          window.setTimeout(() => { window.location.href = `/admin/challenges/${challengeId}`; }, 1400);
          return;
        }
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

const categoryCatalog = document.querySelector("[data-category-catalog]");
if (categoryCatalog) {
  const createRequestHeaders = new WeakMap();
  const validatedIconFiles = new WeakMap();
  const categoryObjectIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  async function validateCategoryIcon(input) {
    const file = input?.files?.[0];
    input?.setCustomValidity("");
    if (!file) {
      if (input) validatedIconFiles.delete(input);
      return null;
    }
    if (validatedIconFiles.get(input) === file) return file;
    if (file.type !== "image/png" && file.type !== "image/svg+xml") {
      input.setCustomValidity("Choose a PNG or SVG image.");
      throw new Error("Custom category logos must be PNG or SVG images.");
    }
    if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > 256 * 1024) {
      input.setCustomValidity("Choose an image no larger than 256 KiB.");
      throw new Error("Custom category logos must be no larger than 256 KiB.");
    }
    if (file.type === "image/svg+xml") {
      let documentRoot;
      try {
        documentRoot = new DOMParser().parseFromString(await file.text(), "image/svg+xml");
      } catch (_error) {
        documentRoot = null;
      }
      const svg = documentRoot?.documentElement;
      const viewBox = svg?.getAttribute("viewBox")?.trim().split(/[\s,]+/).map(Number) || [];
      const safeElements = new Set([
        "svg", "g", "path", "circle", "ellipse", "line", "polyline", "polygon", "rect",
      ]);
      const unsafeNode = svg && [svg, ...svg.querySelectorAll("*")].some(node =>
        node.namespaceURI !== "http://www.w3.org/2000/svg"
        || !safeElements.has(node.localName)
        || Array.from(node.attributes).some(attribute =>
          attribute.name.toLocaleLowerCase().startsWith("on")
          || ["href", "style", "src"].includes(attribute.localName.toLocaleLowerCase())
          || /(?:url\s*\(|javascript:|data:)/i.test(attribute.value)
        ));
      if (!svg || svg.localName !== "svg" || documentRoot.querySelector("parsererror")
          || viewBox.length !== 4 || !viewBox.every(Number.isFinite)
          || viewBox[2] <= 0 || viewBox[2] !== viewBox[3] || unsafeNode) {
        input.setCustomValidity("Choose a valid SVG with a square viewBox.");
        throw new Error("Custom SVG logos must have a square viewBox; unsafe SVG content is rejected by the server.");
      }
      validatedIconFiles.set(input, file);
      return file;
    }
    if (typeof globalThis.createImageBitmap !== "function") {
      input.setCustomValidity("This browser cannot verify image dimensions.");
      throw new Error("This browser cannot verify custom PNG dimensions.");
    }
    let bitmap;
    try {
      bitmap = await globalThis.createImageBitmap(file);
      if (bitmap.width !== 128 || bitmap.height !== 128) {
        input.setCustomValidity("Choose a PNG that is exactly 128 × 128 pixels.");
        throw new Error("Custom PNG logos must be exactly 128 × 128 pixels.");
      }
    } catch (error) {
      if (!input.validationMessage) input.setCustomValidity("Choose a valid PNG image.");
      throw error instanceof Error ? error : new Error("The custom category logo could not be read.");
    } finally {
      bitmap?.close();
    }
    validatedIconFiles.set(input, file);
    return file;
  }

  function categoryIconDataUrl(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.addEventListener("load", () => {
        if (typeof reader.result === "string"
            && (reader.result.startsWith("data:image/png;")
              || reader.result.startsWith("data:image/svg+xml;"))) {
          resolve(reader.result);
        } else {
          reject(new Error("The custom logo preview could not be prepared."));
        }
      }, { once: true });
      reader.addEventListener("error", () => {
        reject(new Error("The custom logo preview could not be read."));
      }, { once: true });
      reader.readAsDataURL(file);
    });
  }

  const syncCategoryEditorPreview = form => {
    const name = form.elements.name.value.trim() || "Category name";
    const preview = form.querySelector("[data-category-preview]");
    const markerMode = form.querySelector('input[name="marker_mode"]:checked')?.value || "name";
    const logoKey = normalizeCategoryLogoKey(markerMode);
    const logoColor = normalizeCategoryLogoColor(form.elements.logo_color?.value);
    const custom = markerMode === "custom";
    const colorFields = form.querySelector("[data-category-logo-color-fields]");
    const customFields = form.querySelector("[data-category-custom-logo-fields]");
    const iconInput = form.querySelector("[data-category-icon-file]");
    const uploadPreview = form.querySelector("[data-category-upload-preview]");
    const existingIcons = Array.from(preview?.querySelectorAll("[data-category-icon-image]") || []);
    if (colorFields) colorFields.hidden = !logoKey;
    if (form.elements.logo_color) form.elements.logo_color.disabled = !logoKey;
    if (customFields) customFields.hidden = !custom;
    if (iconInput) iconInput.disabled = !custom || iconInput.dataset.storageEnabled !== "true";
    preview?.setAttribute("aria-label", `Category marker preview for ${name}`);
    const fallback = syncCategoryFallback(preview, logoKey, name, logoColor);
    for (const svg of form.querySelectorAll("[data-category-logo-picker] svg")) {
      svg.setAttribute("stroke", logoColor);
    }
    if (!custom) {
      if (uploadPreview) uploadPreview.hidden = true;
      for (const existing of existingIcons) {
        existing.onload = null;
        existing.hidden = true;
      }
      if (fallback) fallback.hidden = false;
    } else if (iconInput?.files?.length && uploadPreview?.getAttribute("src")) {
      uploadPreview.hidden = false;
      for (const existing of existingIcons) existing.hidden = true;
      if (fallback) fallback.hidden = true;
    } else if (!iconInput?.files?.length && uploadPreview) {
      uploadPreview.hidden = true;
      for (const existing of existingIcons) prepareCategoryImage(existing, fallback);
    }
  };

  for (const form of document.querySelectorAll("[data-category-form]")) {
    const iconInput = form.querySelector("[data-category-icon-file]");
    const uploadPreview = form.querySelector("[data-category-upload-preview]");
    const preview = form.querySelector("[data-category-preview]");
    const previewFallback = form.querySelector("[data-category-icon-fallback]");
    let previewGeneration = 0;
    form.querySelector("[data-category-name]")?.addEventListener("input", () => syncCategoryEditorPreview(form));
    for (const choice of form.querySelectorAll('input[name="marker_mode"]')) {
      choice.addEventListener("change", () => syncCategoryEditorPreview(form));
    }
    form.elements.logo_color?.addEventListener("input", () => syncCategoryEditorPreview(form));
    iconInput?.addEventListener("change", async () => {
      const generation = ++previewGeneration;
      if (uploadPreview) uploadPreview.hidden = true;
      const errorRegion = form.querySelector("[data-category-form-error]");
      if (errorRegion) errorRegion.textContent = "";
      try {
        const file = await validateCategoryIcon(iconInput);
        if (generation !== previewGeneration) return;
        if (!file) {
          for (const existing of preview?.querySelectorAll("[data-category-icon-image]") || []) {
            prepareCategoryImage(existing, previewFallback);
          }
          if (!preview?.querySelector("[data-category-icon-image]") && previewFallback) {
            previewFallback.hidden = false;
          }
          return;
        }
        if (!uploadPreview) return;
        const previewDataUrl = await categoryIconDataUrl(file);
        if (generation !== previewGeneration) return;
        uploadPreview.src = previewDataUrl;
        uploadPreview.hidden = false;
        if (previewFallback) previewFallback.hidden = true;
        for (const existing of preview?.querySelectorAll("[data-category-icon-image]") || []) {
          existing.hidden = true;
        }
      } catch (error) {
        if (generation !== previewGeneration) return;
        const existingIcons = Array.from(preview?.querySelectorAll("[data-category-icon-image]") || []);
        if (existingIcons.length) {
          for (const existing of existingIcons) prepareCategoryImage(existing, previewFallback);
        } else if (previewFallback) {
          previewFallback.hidden = false;
        }
        if (errorRegion) errorRegion.textContent = error.message || "The custom category logo is invalid.";
      }
    });
    syncCategoryEditorPreview(form);

    form.addEventListener("submit", async event => {
      event.preventDefault();
      const markerMode = form.querySelector('input[name="marker_mode"]:checked')?.value || "name";
      const logoKey = normalizeCategoryLogoKey(markerMode);
      const custom = markerMode === "custom";
      let iconFile;
      if (custom) {
        try {
          iconFile = await validateCategoryIcon(iconInput);
        } catch (error) {
          form.querySelector("[data-category-form-error]").textContent = error.message;
          iconInput?.reportValidity();
          return;
        }
        if (!iconFile && !categoryObjectIdPattern.test(form.dataset.categoryIconObjectId || "")) {
          form.querySelector("[data-category-form-error]").textContent = "Choose a PNG or SVG file for the custom marker.";
          iconInput?.setCustomValidity("Choose a PNG or SVG file.");
          iconInput?.reportValidity();
          return;
        }
      }
      if (!form.reportValidity()) return;
      const errorRegion = form.querySelector("[data-category-form-error]");
      const submit = form.querySelector('button[type="submit"]');
      const mode = form.dataset.categoryMode;
      const categoryId = form.dataset.categoryId;
      if (errorRegion) errorRegion.textContent = "";
      if (mode === "create" && !createRequestHeaders.has(form)) {
        createRequestHeaders.set(form, idempotencyHeaders());
      }
      setBusy(submit, true, mode === "create" ? "Creating…" : "Saving…");
      try {
        const result = await apiRequest(
          mode === "create"
            ? "/api/v1/admin/challenge-categories"
            : `/api/v1/admin/challenge-categories/${categoryId}`,
          {
            method: mode === "create" ? "POST" : "PATCH",
            headers: mode === "create" ? createRequestHeaders.get(form) : undefined,
            body: {
              name: form.elements.name.value.trim(),
              logo_key: logoKey || null,
              logo_color: logoKey
                ? normalizeCategoryLogoColor(form.elements.logo_color?.value)
                : null,
            },
          },
        );
        const category = result.data;
        const savedCategoryId = Number(category?.id || categoryId);
        if (!Number.isSafeInteger(savedCategoryId) || savedCategoryId < 1) {
          throw new Error("The category service returned an invalid identifier.");
        }
        const label = category?.name || form.elements.name.value.trim();
        const currentIconObjectId = form.dataset.categoryIconObjectId;
        if (mode === "edit" && !custom && categoryObjectIdPattern.test(currentIconObjectId || "")) {
          try {
            await apiRequest(`/api/v1/admin/challenge-categories/${savedCategoryId}/icon/${currentIconObjectId}`, { method: "DELETE" });
          } catch (error) {
            showToast(`Category “${label}” was saved, but its previous custom logo could not be removed: ${error.message}`, "warning", 7000);
            window.setTimeout(() => window.location.reload(), 1400);
            return;
          }
        }
        if (iconFile) {
          try {
            await uploadObject(iconFile, {
              purpose: "category_icon",
              category_id: savedCategoryId,
            });
          } catch (error) {
            showToast(`Category “${label}” was saved, but its icon was not attached: ${error.message}`, "warning", 7000);
            window.setTimeout(() => window.location.reload(), 1400);
            return;
          }
        }
        showToast(`Category “${label}” ${mode === "create" ? "created" : "updated"}.`);
        window.setTimeout(() => window.location.reload(), 350);
      } catch (error) {
        if (errorRegion) errorRegion.textContent = error.message || "The category could not be saved.";
        setBusy(submit, false);
      }
    });

    form.querySelector("[data-remove-category-icon]")?.addEventListener("click", async event => {
      const categoryId = form.dataset.categoryId;
      const iconObjectId = event.currentTarget.dataset.categoryIconObjectId;
      const categoryName = form.elements.name.value.trim();
      const errorRegion = form.querySelector("[data-category-form-error]");
      if (!categoryId || !categoryObjectIdPattern.test(iconObjectId || "")) {
        if (errorRegion) errorRegion.textContent = "The current icon identifier is invalid. Refresh this page before trying again.";
        return;
      }
      if (!window.confirm(`Remove the custom logo from “${categoryName}”? Players will see its built-in logo or name instead.`)) return;
      if (errorRegion) errorRegion.textContent = "";
      setBusy(event.currentTarget, true, "Removing…");
      try {
        await apiRequest(`/api/v1/admin/challenge-categories/${categoryId}/icon/${iconObjectId}`, { method: "DELETE" });
        showToast(`Custom logo removed from “${categoryName}”.`);
        window.setTimeout(() => window.location.reload(), 350);
      } catch (error) {
        if (errorRegion) {
          errorRegion.textContent = error.status === 409
            ? "This custom category logo changed since the page loaded. Refresh the page before trying again."
            : error.message || "The custom category logo could not be removed.";
        }
        setBusy(event.currentTarget, false);
      }
    });

    form.querySelector("[data-delete-category]")?.addEventListener("click", async event => {
      const categoryId = form.dataset.categoryId;
      const categoryName = form.elements.name.value.trim();
      if (!categoryId || !window.confirm(`Delete category “${categoryName}”? This cannot be undone.`)) return;
      const errorRegion = form.querySelector("[data-category-form-error]");
      if (errorRegion) errorRegion.textContent = "";
      setBusy(event.currentTarget, true, "Deleting…");
      try {
        await apiRequest(`/api/v1/admin/challenge-categories/${categoryId}`, { method: "DELETE" });
        showToast(`Category “${categoryName}” deleted.`);
        window.setTimeout(() => window.location.reload(), 350);
      } catch (error) {
        if (errorRegion) errorRegion.textContent = error.message || "The category could not be deleted.";
        setBusy(event.currentTarget, false);
      }
    });
  }
}

const pageCatalog = document.querySelector("[data-page-catalog]");
if (pageCatalog) {
  const createRequestHeaders = new WeakMap();

  function pageHtml(form) {
    const value = form.elements.content?.value || "";
    if (value.includes("\0")) throw new Error("Page HTML cannot contain NUL characters.");
    if (new TextEncoder().encode(value).byteLength > 256 * 1024) {
      throw new Error("Page HTML must be no larger than 256 KiB.");
    }
    return value;
  }

  function pageEndpoint(form) {
    return (form.elements.endpoint?.value || "")
      .trim()
      .replace(/^\/+|\/+$/g, "")
      .toLocaleLowerCase();
  }

  for (const form of document.querySelectorAll("[data-page-form]")) {
    form.addEventListener("submit", async event => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const mode = form.dataset.pageMode;
      const pageType = form.dataset.pageType;
      const pageId = Number(form.dataset.pageId || 0);
      const errorRegion = form.querySelector("[data-page-form-error]");
      const submit = form.querySelector('button[type="submit"]');
      if (errorRegion) errorRegion.textContent = "";
      try {
        const body = {};
        if (mode === "create" || pageType !== "system") {
          body.label = form.elements.label.value.trim();
        }
        if (mode === "create" || pageType === "custom") body.endpoint = pageEndpoint(form);
        if (pageType !== "home") {
          body.visibility = form.elements.visibility.value;
          body.navigation_order = Number(form.elements.navigation_order.value);
        }
        if (mode === "create" || pageType !== "system") body.content = pageHtml(form);
        if (mode === "edit") {
          const revision = Number(form.dataset.pageRevision);
          if (!Number.isSafeInteger(pageId) || pageId < 1
              || !Number.isSafeInteger(revision) || revision < 1) {
            throw new Error("This page record is invalid. Refresh before saving.");
          }
          body.revision = revision;
        } else if (!createRequestHeaders.has(form)) {
          createRequestHeaders.set(form, idempotencyHeaders());
        }
        setBusy(submit, true);
        const result = await apiRequest(
          mode === "create" ? "/api/v1/pages" : `/api/v1/pages/${pageId}`,
          {
            method: mode === "create" ? "POST" : "PATCH",
            headers: mode === "create" ? createRequestHeaders.get(form) : undefined,
            body,
          },
        );
        const label = result.data?.label || body.label || "Page";
        showToast(`${label} ${mode === "create" ? "created" : "updated"}.`);
        window.setTimeout(() => window.location.reload(), 350);
      } catch (error) {
        if (errorRegion) errorRegion.textContent = error.message || "The page could not be saved.";
        setBusy(submit, false);
      }
    });

    form.querySelector("[data-delete-page]")?.addEventListener("click", async event => {
      const pageId = Number(form.dataset.pageId || 0);
      const label = form.elements.label.value.trim();
      const errorRegion = form.querySelector("[data-page-form-error]");
      if (!Number.isSafeInteger(pageId) || pageId < 1) return;
      if (!window.confirm(`Delete page “${label}”? This cannot be undone.`)) return;
      if (errorRegion) errorRegion.textContent = "";
      setBusy(event.currentTarget, true, "Deleting…");
      try {
        await apiRequest(`/api/v1/pages/${pageId}`, { method: "DELETE" });
        showToast(`${label} deleted.`);
        window.setTimeout(() => window.location.reload(), 350);
      } catch (error) {
        if (errorRegion) errorRegion.textContent = error.message || "The page could not be deleted.";
        setBusy(event.currentTarget, false);
      }
    });
  }
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

function acceptConfigPayload(section, payload) {
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
}

const userModeDialog = document.querySelector("[data-user-mode-transition-dialog]");
const userModeDialogTitle = userModeDialog?.querySelector("[data-user-mode-transition-title]");
const userModeDialogSummary = userModeDialog?.querySelector("[data-user-mode-transition-summary]");
const userModeDialogStatus = userModeDialog?.querySelector("[data-user-mode-transition-status]");
const userModeDialogBlockers = userModeDialog?.querySelector("[data-user-mode-transition-blockers]");
const userModeDialogBlockerList = userModeDialog?.querySelector("[data-user-mode-transition-blocker-list]");
const userModeDialogLogicWarning = userModeDialog?.querySelector("[data-user-mode-transition-logic-warning]");
const userModeDialogLogicMessage = userModeDialog?.querySelector("[data-user-mode-transition-logic-message]");
const userModeDialogCounts = userModeDialog?.querySelector("[data-user-mode-transition-counts]");
const userModeDialogExpiry = userModeDialog?.querySelector("[data-user-mode-transition-expiry]");
const userModeDialogConfirmation = userModeDialog?.querySelector("[data-user-mode-transition-confirmation]");
const userModeDialogPhrase = userModeDialog?.querySelector("[data-user-mode-transition-phrase]");
const userModeDialogInput = userModeDialog?.querySelector("[data-user-mode-transition-confirmation-input]");
const userModeDialogConfirm = userModeDialog?.querySelector("[data-user-mode-transition-confirm]");
const userModeDialogRetry = userModeDialog?.querySelector("[data-user-mode-transition-retry]");
const userModeDialogCancel = userModeDialog?.querySelector("[data-user-mode-transition-cancel]");
const userModeDialogClose = userModeDialog?.querySelector("[data-user-mode-transition-close]");

const userModeImpactLabels = {
  participants: "Participant credentials rotated (accounts preserved)",
  teams: "Teams deleted",
  memberships: "Team memberships removed",
  submissions: "Submissions deleted",
  solves: "Solves deleted",
  awards: "Awards deleted",
  unlocks: "Challenge unlocks deleted",
  tracking: "Challenge-open tracking deleted",
  dynamic_challenges: "Dynamic challenge values reset",
  team_logic_challenges: "Team-specific challenge definitions preserved",
  team_notifications: "Team notifications deleted",
  team_field_entries: "Team profile fields deleted",
  team_comments: "Team comments deleted",
  team_objects: "Team-owned object records matched (teams removed)",
  user_objects: "Participant competition-object records matched",
  sessions: "Participant browser sessions revoked",
  api_tokens: "Participant API tokens revoked",
  active_runtimes: "Active private instances (must be stopped)",
};

let pendingUserModeTransition = null;
let userModeTransitionPreview = null;
let userModeTransitionExecuting = false;
let userModePreviewRequest = 0;

function accountModeLabel(mode) {
  return mode === "teams" ? "Teams" : "Individual users";
}

function setUserModeDialogStatus(message, tone = "") {
  if (!userModeDialogStatus) return;
  userModeDialogStatus.textContent = message;
  userModeDialogStatus.classList.remove("danger", "warning", "good");
  if (tone) userModeDialogStatus.classList.add(tone);
}

function userModePreviewExpiresAt(value) {
  const date = new Date(value || "");
  return Number.isFinite(date.getTime())
    ? `Valid until ${date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`
    : "Fresh preview required";
}

function syncUserModeConfirmation() {
  const blocked = !userModeTransitionPreview || userModeTransitionPreview.blocked;
  const matches = userModeDialogInput?.value === userModeTransitionPreview?.confirmation_phrase;
  if (userModeDialogConfirm) {
    userModeDialogConfirm.disabled = userModeTransitionExecuting || blocked || !matches;
  }
}

function setUserModeDialogBusy(busy) {
  userModeTransitionExecuting = busy;
  userModeDialog?.setAttribute("aria-busy", String(busy));
  if (userModeDialogInput) userModeDialogInput.disabled = busy || Boolean(userModeTransitionPreview?.blocked);
  if (userModeDialogCancel) userModeDialogCancel.disabled = busy;
  if (userModeDialogClose) userModeDialogClose.disabled = busy;
  if (userModeDialogRetry) userModeDialogRetry.disabled = busy;
  if (busy) setBusy(userModeDialogConfirm, true, "Switching…");
  else {
    setBusy(userModeDialogConfirm, false);
    syncUserModeConfirmation();
  }
}

function renderUserModeImpact(preview) {
  if (!userModeDialogCounts) return;
  userModeDialogCounts.replaceChildren();
  const affected = preview?.affected && typeof preview.affected === "object"
    ? preview.affected
    : {};
  for (const [key, label] of Object.entries(userModeImpactLabels)) {
    const row = document.createElement("tr");
    const description = document.createElement("td");
    const count = document.createElement("td");
    description.textContent = label;
    count.className = "table-actions mono";
    count.textContent = String(affected[key] ?? 0);
    row.append(description, count);
    userModeDialogCounts.append(row);
  }
}

function renderUserModeBlockers(preview) {
  if (!userModeDialogBlockerList || !userModeDialogBlockers) return;
  userModeDialogBlockerList.replaceChildren();
  const blockers = Array.isArray(preview?.blockers) ? preview.blockers : [];
  for (const blocker of blockers) {
    const item = document.createElement("li");
    const count = blocker && blocker.count !== undefined ? ` (${blocker.count})` : "";
    item.textContent = `${blocker?.message || "Resolve this blocker before continuing."}${count}`;
    userModeDialogBlockerList.append(item);
  }
  userModeDialogBlockers.hidden = !preview?.blocked;
}

async function loadUserModeTransitionPreview({ refreshed = false } = {}) {
  if (!pendingUserModeTransition || !userModeDialog) return;
  const requestId = ++userModePreviewRequest;
  const targetMode = pendingUserModeTransition.targetMode;
  userModeTransitionPreview = null;
  if (userModeDialogInput) {
    userModeDialogInput.value = "";
    userModeDialogInput.disabled = true;
  }
  if (userModeDialogPhrase) userModeDialogPhrase.textContent = "";
  if (userModeDialogConfirmation) userModeDialogConfirmation.hidden = true;
  if (userModeDialogBlockers) userModeDialogBlockers.hidden = true;
  if (userModeDialogLogicWarning) userModeDialogLogicWarning.hidden = true;
  if (userModeDialogRetry) userModeDialogRetry.hidden = true;
  if (userModeDialogExpiry) userModeDialogExpiry.textContent = "Preview loading";
  if (userModeDialogCounts) {
    userModeDialogCounts.innerHTML = '<tr><td colspan="2" class="admin-empty-row">Loading affected record counts…</td></tr>';
  }
  setUserModeDialogStatus("Preparing a fresh transition preview…");
  syncUserModeConfirmation();

  try {
    const parameters = new URLSearchParams({ target: targetMode });
    const result = await apiRequest(`/api/v1/views/admin/user-mode-transition?${parameters}`);
    if (requestId !== userModePreviewRequest || pendingUserModeTransition?.targetMode !== targetMode) return;
    const preview = result.data;
    if (!preview || preview.target_mode !== targetMode || !["users", "teams"].includes(preview.source_mode)) {
      throw new Error("The API returned an invalid account-mode preview.");
    }
    if (preview.source_mode === preview.target_mode) {
      acceptConfigPayload(pendingUserModeTransition.section, { user_mode: targetMode });
      userModeDialog.close();
      showToast(`${accountModeLabel(targetMode)} is already the active account mode.`, "warning");
      window.setTimeout(() => window.location.reload(), 450);
      return;
    }
    userModeTransitionPreview = preview;
    if (userModeDialogTitle) userModeDialogTitle.textContent = `Switch to ${accountModeLabel(targetMode)}`;
    if (userModeDialogSummary) {
      userModeDialogSummary.textContent = targetMode === "teams"
        ? "Participant accounts are preserved, but competition history, any existing teams and memberships, and participant/team competition objects are retired. Every participant starts without a team."
        : "Participant accounts are preserved, but competition history, memberships, teams, and participant/team competition objects are retired.";
    }
    renderUserModeImpact(preview);
    renderUserModeBlockers(preview);
    const teamLogicChallenges = preview.affected?.team_logic_challenges ?? 0;
    const showLogicWarning = targetMode === "users" && Number(teamLogicChallenges) > 0;
    if (userModeDialogLogicMessage) {
      userModeDialogLogicMessage.textContent = `${teamLogicChallenges} challenge definition${Number(teamLogicChallenges) === 1 ? "" : "s"} use team-specific logic. `
        + `${Number(teamLogicChallenges) === 1 ? "It is" : "They are"} preserved, but must be reviewed after switching to individual users.`;
    }
    if (userModeDialogLogicWarning) userModeDialogLogicWarning.hidden = !showLogicWarning;
    if (userModeDialogExpiry) userModeDialogExpiry.textContent = userModePreviewExpiresAt(preview.expires_at);
    if (userModeDialogPhrase) userModeDialogPhrase.textContent = preview.confirmation_phrase || "";
    const blocked = Boolean(preview.blocked || !preview.preview_token || !preview.confirmation_phrase);
    if (userModeDialogConfirmation) userModeDialogConfirmation.hidden = blocked;
    if (userModeDialogInput) userModeDialogInput.disabled = blocked;
    if (userModeDialogRetry) userModeDialogRetry.hidden = !blocked;
    if (blocked) {
      setUserModeDialogStatus("Resolve every blocker, then refresh the preview.", "danger");
    } else {
      setUserModeDialogStatus(
        refreshed
          ? "The database changed while you were reviewing it. Counts were refreshed; review them and confirm again."
          : "Review these fresh counts and type the confirmation phrase to continue.",
        refreshed ? "warning" : "",
      );
      window.requestAnimationFrame(() => userModeDialogInput?.focus());
    }
    syncUserModeConfirmation();
  } catch (error) {
    if (requestId !== userModePreviewRequest) return;
    if (error.status === 401) {
      window.location.assign("/login");
      return;
    }
    userModeTransitionPreview = null;
    if (userModeDialogExpiry) userModeDialogExpiry.textContent = "Preview unavailable";
    if (userModeDialogRetry) userModeDialogRetry.hidden = false;
    setUserModeDialogStatus(
      error.message || "The transition preview could not be loaded.",
      "danger",
    );
    syncUserModeConfirmation();
  }
}

function openUserModeTransition(section, targetMode) {
  if (!userModeDialog) {
    showToast("The account-mode transition panel is unavailable. Refresh this page and try again.", "error", 5500);
    return;
  }
  if (!["users", "teams"].includes(targetMode)) {
    showToast("Choose a valid account mode.", "error", 5500);
    return;
  }
  pendingUserModeTransition = { section, targetMode };
  userModeTransitionPreview = null;
  document.body.classList.add("user-mode-dialog-open");
  if (typeof userModeDialog.showModal === "function") userModeDialog.showModal();
  else userModeDialog.setAttribute("open", "");
  loadUserModeTransitionPreview();
}

function closeUserModeTransition() {
  if (!userModeDialog || userModeTransitionExecuting) return;
  if (typeof userModeDialog.close === "function") userModeDialog.close();
  else userModeDialog.removeAttribute("open");
}

userModeDialogInput?.addEventListener("input", syncUserModeConfirmation);
userModeDialogInput?.addEventListener("keydown", event => {
  if (event.key !== "Enter" || userModeDialogConfirm?.disabled) return;
  event.preventDefault();
  userModeDialogConfirm.click();
});
userModeDialogCancel?.addEventListener("click", closeUserModeTransition);
userModeDialogClose?.addEventListener("click", closeUserModeTransition);
userModeDialogRetry?.addEventListener("click", () => loadUserModeTransitionPreview());
userModeDialog?.addEventListener("cancel", event => {
  if (userModeTransitionExecuting) event.preventDefault();
});
userModeDialog?.addEventListener("close", () => {
  userModePreviewRequest += 1;
  document.body.classList.remove("user-mode-dialog-open");
  userModeTransitionPreview = null;
  pendingUserModeTransition?.section.querySelector("[data-user-mode-input]")?.focus();
  pendingUserModeTransition = null;
});

userModeDialogConfirm?.addEventListener("click", async () => {
  const pending = pendingUserModeTransition;
  const preview = userModeTransitionPreview;
  if (!pending || !preview || preview.blocked) return;
  if (userModeDialogInput?.value !== preview.confirmation_phrase) return;
  setUserModeDialogBusy(true);
  setUserModeDialogStatus("Applying the destructive transition. Do not close this page…", "warning");
  try {
    await apiRequest("/api/v1/configs/user-mode-transition", {
      method: "POST",
      body: {
        target_mode: pending.targetMode,
        confirmation: userModeDialogInput.value,
        preview_token: preview.preview_token,
      },
    });
    acceptConfigPayload(pending.section, { user_mode: pending.targetMode });

    setUserModeDialogBusy(false);
    closeUserModeTransition();
    showToast(`Account mode switched to ${accountModeLabel(pending.targetMode)}.`);
    window.setTimeout(() => window.location.reload(), 450);
  } catch (error) {
    setUserModeDialogBusy(false);
    if (error.status === 401) {
      window.location.assign("/login");
      return;
    }
    if (error.status === 409) {
      await loadUserModeTransitionPreview({ refreshed: true });
      return;
    }
    setUserModeDialogStatus(error.message || "The account-mode transition failed.", "danger");
    if (userModeDialogRetry) userModeDialogRetry.hidden = false;
  }
});

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
    const userModeInput = section.querySelector("[data-user-mode-input]");
    const userModeDirty = Boolean(
      userModeInput
      && userModeInput.dataset.staticDisabled !== "true"
      && userModeInput.value !== userModeInput.dataset.initialControl,
    );
    const anotherInputDirty = Array.from(section.querySelectorAll("[data-config-input]"))
      .some(input => input !== userModeInput
        && input.dataset.staticDisabled !== "true"
        && input.value !== input.dataset.initialControl);
    const anotherSecretDirty = Array.from(section.querySelectorAll("[data-secret-control]"))
      .some(secret => {
        const action = secret.querySelector("[data-secret-action]");
        return Boolean(action
          && action.dataset.staticDisabled !== "true"
          && action.value !== "keep");
      });
    if (userModeDirty && (anotherInputDirty || anotherSecretDirty)) {
      showToast(
        "Switch account mode separately. Revert to the current mode and save other settings first; team-only settings can be saved after the switch.",
        "warning",
        7000,
      );
      userModeInput.focus();
      return;
    }
    if (!section.reportValidity()) return;
    const payload = {};
    const dangers = [];
    try {
      for (const input of section.querySelectorAll("[data-config-input]")) {
        if (input.disabled || input.value === input.dataset.initialControl) continue;
        payload[input.dataset.configKey] = configInputValue(input);
        const danger = input.closest("[data-config-setting]")?.dataset.configDanger;
        if (danger && input.dataset.configKey !== "user_mode") dangers.push(danger);
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
    if (Object.hasOwn(payload, "user_mode")) {
      openUserModeTransition(section, payload.user_mode);
      return;
    }
    const buttons = section.querySelectorAll('button[type="submit"]');
    for (const button of buttons) setBusy(button, true);
    try {
      await apiRequest("/api/v1/configs", { method: "PATCH", body: payload });
      acceptConfigPayload(section, payload);
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

const machineEnrollmentForm = document.querySelector("[data-machine-enrollment-form]");
machineEnrollmentForm?.addEventListener("submit", async event => {
  event.preventDefault();
  if (!machineEnrollmentForm.reportValidity()) return;
  const button = machineEnrollmentForm.querySelector('button[type="submit"]');
  const hostname = machineEnrollmentForm.elements.hostname.value.trim();
  if (hostname.includes("://")) {
    showToast("Enter a hostname or IP address, not a URL.", "error", 5500);
    machineEnrollmentForm.elements.hostname.focus();
    return;
  }
  const sshUser = machineEnrollmentForm.elements.name.value.trim();
  if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(sshUser) || ["root", "toor"].includes(sshUser)) {
    showToast("Enter an existing non-root Linux username using lowercase letters, numbers, underscores, or hyphens.", "error", 5500);
    machineEnrollmentForm.elements.name.focus();
    return;
  }
  const body = {
    name: sshUser,
    hostname,
    ssh_port: Number(machineEnrollmentForm.elements.ssh_port.value),
  };
  setBusy(button, true, "Registering…");
  try {
    await apiRequest("/api/v1/admin/ssh/hosts", {
      method: "POST",
      headers: idempotencyHeaders(),
      body,
    });
    showToast("Host registered. Preparing its browser-console access key.");
    window.setTimeout(() => window.location.reload(), 500);
  } catch (error) {
    showToast(error.message || "The machine could not be registered.", "error", 5500);
    setBusy(button, false);
  }
});

for (const button of document.querySelectorAll("[data-machine-refresh]")) {
  button.addEventListener("click", () => window.location.reload());
}

for (const button of document.querySelectorAll("[data-retry-machine]")) {
  button.addEventListener("click", async () => {
    setBusy(button, true, "Retrying…");
    try {
      await apiRequest(
        `/api/v1/admin/ssh/hosts/${encodeURIComponent(button.dataset.retryMachine)}/identity/retry`,
        { method: "POST" },
      );
      showToast("Access-key preparation queued.");
      window.setTimeout(() => window.location.reload(), 450);
    } catch (error) {
      showToast(error.message || "Access-key preparation could not be retried.", "error", 5500);
      setBusy(button, false);
    }
  });
}

async function copyMachineValue(button) {
  const card = button.closest("[data-machine-card]");
  const value = card?.querySelector("[data-machine-authorized-line]")?.textContent || "";
  if (!value) return;
  let fallback = null;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
    } else {
      fallback = document.createElement("textarea");
      fallback.className = "sr-only";
      fallback.value = value;
      fallback.setAttribute("readonly", "");
      document.body.append(fallback);
      fallback.select();
      const copied = document.execCommand("copy");
      if (!copied) throw new Error("Clipboard unavailable");
    }
    showToast("authorized_keys line copied.");
  } catch (_error) {
    showToast("Copy failed. Select the text and copy it manually.", "error", 5500);
  } finally {
    fallback?.remove();
  }
}

for (const button of document.querySelectorAll("[data-machine-copy]")) {
  button.addEventListener("click", () => copyMachineValue(button));
}

for (const button of document.querySelectorAll("[data-remove-machine]")) {
  button.addEventListener("click", async () => {
    if (!window.confirm(
      "Remove this host? The record and portal-held access key will be deleted. The installed authorized_keys line remains on the remote account and must be removed manually.",
    )) return;
    setBusy(button, true, "Removing…");
    try {
      await apiRequest(
        `/api/v1/admin/ssh/hosts/${encodeURIComponent(button.dataset.removeMachine)}`,
        { method: "DELETE" },
      );
      button.closest("[data-machine-card]")?.remove();
      showToast("Host removed.");
      window.setTimeout(() => window.location.reload(), 350);
    } catch (error) {
      showToast(error.message || "The host could not be removed.", "error", 5500);
      setBusy(button, false);
    }
  });
}

const SSH_WEBSOCKET_PATH = "/bff/ssh/terminal";
const SSH_WEBSOCKET_PROTOCOL = "ctfzone.ssh.v1";
const SSH_MAX_BUFFERED_INPUT = 1024 * 1024;
const sshHostKeyDialog = document.querySelector("[data-host-key-dialog]");
const sshHostKeyConfirm = sshHostKeyDialog?.querySelector("[data-host-key-confirm]");
const sshHostKeyTrust = sshHostKeyDialog?.querySelector("[data-host-key-trust]");
const sshTerminalDialog = document.querySelector("[data-ssh-terminal-dialog]");
const sshTerminalContainer = sshTerminalDialog?.querySelector("[data-ssh-terminal]");
const sshTerminalStatus = sshTerminalDialog?.querySelector("[data-ssh-terminal-status]");
let activeSshSession = null;

function boundedTerminalSize(terminal) {
  return {
    cols: Math.min(500, Math.max(20, Number(terminal?.cols) || 120)),
    rows: Math.min(200, Math.max(5, Number(terminal?.rows) || 40)),
  };
}

function validFingerprint(value) {
  return typeof value === "string"
    && /^SHA256:[A-Za-z0-9+/]{43}$/.test(value);
}

function validPublicHostKey(value, algorithm) {
  if (algorithm !== "ssh-ed25519" || typeof value !== "string") return false;
  const match = /^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})$/.exec(value);
  if (!match) return false;
  try {
    const decoded = globalThis.atob(match[1]);
    const prefix = "\0\0\0\x0bssh-ed25519\0\0\0\x20";
    return decoded.length === prefix.length + 32 && decoded.startsWith(prefix);
  } catch (_error) {
    return false;
  }
}

function validUuid(value) {
  return typeof value === "string"
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

async function requestSshTicket(hostId, purpose) {
  if (!validUuid(hostId) || !["probe", "terminal"].includes(purpose)) {
    throw new Error("The SSH connection request is invalid.");
  }
  const { data } = await apiRequest(
    `/api/v1/admin/ssh/hosts/${encodeURIComponent(hostId)}/tickets`,
    { method: "POST", body: { purpose } },
  );
  const path = data?.websocket_path;
  const expiry = Date.parse(data?.expires_at || "");
  if (
    typeof data?.ticket !== "string"
    || !/^[A-Za-z0-9_-]{43}$/.test(data.ticket)
    || data?.purpose !== purpose
    || path !== SSH_WEBSOCKET_PATH
    || !Number.isFinite(expiry)
    || expiry <= Date.now()
    || expiry > Date.now() + 5 * 60 * 1000
  ) {
    throw new Error("The SSH gateway returned an invalid connection ticket.");
  }
  return { ticket: data.ticket, path };
}

function openSshGateway(ticketData, { terminal = null, onControl, onBinary }) {
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${scheme}//${window.location.host}${ticketData.path}`, SSH_WEBSOCKET_PROTOCOL);
  socket.binaryType = "arraybuffer";
  let oneTimeTicket = ticketData.ticket;
  socket.addEventListener("open", () => {
    const size = boundedTerminalSize(terminal);
    socket.send(JSON.stringify({
      type: "auth",
      ticket: oneTimeTicket,
      cols: size.cols,
      rows: size.rows,
      term: "xterm-256color",
    }));
    oneTimeTicket = "";
  }, { once: true });
  socket.addEventListener("close", () => { oneTimeTicket = ""; }, { once: true });
  socket.addEventListener("message", async event => {
    if (typeof event.data === "string") {
      if (event.data.length > 8192) {
        socket.close(1008, "control frame too large");
        return;
      }
      let control;
      try { control = JSON.parse(event.data); } catch (_error) {
        socket.close(1008, "invalid control frame");
        return;
      }
      onControl?.(control, socket);
      return;
    }
    let bytes;
    if (event.data instanceof ArrayBuffer) bytes = new Uint8Array(event.data);
    else if (event.data instanceof Blob) bytes = new Uint8Array(await event.data.arrayBuffer());
    else {
      socket.close(1008, "invalid terminal frame");
      return;
    }
    onBinary?.(bytes, socket);
  });
  return socket;
}

function machineTarget(card) {
  return `${card?.dataset.machineUser || "invalid"}@${card?.dataset.machineHost || "invalid"}:${card?.dataset.machinePort || "0"}`;
}

function safeSshDiagnostic(value, fallback) {
  const message = typeof value === "string" ? value : fallback;
  return message.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").slice(0, 300) || fallback;
}

function clearHostKeyDialog() {
  if (!sshHostKeyDialog) return;
  for (const key of ["hostId", "candidateId", "hostRevision", "fingerprint"]) {
    delete sshHostKeyDialog.dataset[key];
  }
  sshHostKeyDialog.querySelector("[data-host-key-target]").textContent = "";
  sshHostKeyDialog.querySelector("[data-host-key-algorithm]").textContent = "";
  sshHostKeyDialog.querySelector("[data-host-key-fingerprint]").textContent = "";
  sshHostKeyDialog.querySelector("[data-host-key-public]").textContent = "";
  if (sshHostKeyConfirm) sshHostKeyConfirm.checked = false;
  if (sshHostKeyTrust) sshHostKeyTrust.disabled = true;
}

sshHostKeyConfirm?.addEventListener("change", () => {
  if (sshHostKeyTrust) sshHostKeyTrust.disabled = !sshHostKeyConfirm.checked;
});
sshHostKeyDialog?.addEventListener("close", clearHostKeyDialog);

for (const button of document.querySelectorAll("[data-probe-machine]")) {
  button.addEventListener("click", async () => {
    const card = button.closest("[data-machine-card]");
    const hostId = button.dataset.probeMachine;
    setBusy(button, true, "Inspecting…");
    let received = false;
    try {
      const ticket = await requestSshTicket(hostId, "probe");
      const socket = openSshGateway(ticket, {
        onControl(control, connection) {
          if (control?.type === "host_key") {
            const revision = Number(control.host_revision);
            if (
              received
              || !validUuid(control.session_id)
              || !validUuid(control.candidate_id)
              || !Number.isSafeInteger(revision)
              || revision <= 0
              || typeof control.algorithm !== "string"
              || !validFingerprint(control.fingerprint)
              || !validPublicHostKey(control.public_key, control.algorithm)
            ) {
              connection.close(1008, "invalid host-key result");
              return;
            }
            received = true;
            clearHostKeyDialog();
            sshHostKeyDialog.dataset.hostId = hostId;
            sshHostKeyDialog.dataset.candidateId = control.candidate_id;
            sshHostKeyDialog.dataset.hostRevision = String(revision);
            sshHostKeyDialog.dataset.fingerprint = control.fingerprint;
            sshHostKeyDialog.querySelector("[data-host-key-target]").textContent = machineTarget(card);
            sshHostKeyDialog.querySelector("[data-host-key-algorithm]").textContent = control.algorithm;
            sshHostKeyDialog.querySelector("[data-host-key-fingerprint]").textContent = control.fingerprint;
            sshHostKeyDialog.querySelector("[data-host-key-public]").textContent = control.public_key;
            sshHostKeyDialog.showModal();
            connection.close(1000, "probe complete");
          } else if (control?.type === "error") {
            received = true;
            showToast(safeSshDiagnostic(control.message, "The SSH host-key inspection failed."), "error", 6000);
            connection.close(1000, "probe failed");
          } else {
            connection.close(1008, "unexpected probe response");
          }
        },
        onBinary(_bytes, connection) {
          connection.close(1008, "unexpected probe data");
        },
      });
      socket.addEventListener("close", () => {
        if (!received) showToast("The SSH host-key inspection ended without a result.", "error", 6000);
        setBusy(button, false);
      }, { once: true });
      socket.addEventListener("error", () => {
        received = true;
        showToast("The SSH gateway could not inspect this host.", "error", 6000);
      }, { once: true });
    } catch (error) {
      showToast(safeSshDiagnostic(error?.message, "The SSH host-key inspection could not start."), "error", 6000);
      setBusy(button, false);
    }
  });
}

sshHostKeyTrust?.addEventListener("click", async () => {
  if (!sshHostKeyDialog || !sshHostKeyConfirm?.checked) return;
  const hostId = sshHostKeyDialog.dataset.hostId;
  const candidateId = sshHostKeyDialog.dataset.candidateId;
  const fingerprint = sshHostKeyDialog.dataset.fingerprint;
  const revision = Number(sshHostKeyDialog.dataset.hostRevision);
  if (!validUuid(hostId) || !validUuid(candidateId) || !validFingerprint(fingerprint) || !Number.isSafeInteger(revision)) {
    showToast("The inspected host-key result is no longer valid.", "error", 5500);
    clearHostKeyDialog();
    sshHostKeyDialog.close();
    return;
  }
  setBusy(sshHostKeyTrust, true, "Trusting…");
  try {
    await apiRequest(
      `/api/v1/admin/ssh/hosts/${encodeURIComponent(hostId)}/host-key/trust`,
      { method: "POST", body: { candidate_id: candidateId, fingerprint, revision } },
    );
    clearHostKeyDialog();
    sshHostKeyDialog.close();
    showToast("Host identity trusted. The browser terminal is now available.");
    window.setTimeout(() => window.location.reload(), 450);
  } catch (error) {
    showToast(error.message || "The host key could not be trusted.", "error", 6000);
    setBusy(sshHostKeyTrust, false);
  }
});

function setTerminalStatus(message, kind = "pending") {
  if (!sshTerminalStatus) return;
  sshTerminalStatus.textContent = message;
  sshTerminalStatus.className = `status-pill ${kind}`;
}

function disposeActiveSshSession() {
  if (!activeSshSession) return;
  activeSshSession.resizeObserver?.disconnect();
  if (activeSshSession.resizeHandler) {
    window.removeEventListener("resize", activeSshSession.resizeHandler);
  }
  activeSshSession.socket?.close(1000, "administrator disconnected");
  activeSshSession.inputDisposable?.dispose();
  activeSshSession.terminal?.dispose();
  activeSshSession = null;
  if (sshTerminalContainer) sshTerminalContainer.replaceChildren();
  setTerminalStatus("Disconnected");
}

for (const button of document.querySelectorAll("[data-connect-machine]")) {
  button.addEventListener("click", async () => {
    if (button.disabled || button.getAttribute("aria-disabled") === "true") return;
    const TerminalClass = globalThis.Terminal;
    const FitAddonClass = globalThis.FitAddon?.FitAddon;
    if (!sshTerminalDialog || !sshTerminalContainer || !TerminalClass || !FitAddonClass) {
      showToast("The browser terminal assets are unavailable.", "error", 6000);
      return;
    }
    disposeActiveSshSession();
    const card = button.closest("[data-machine-card]");
    const target = machineTarget(card);
    const expectedHostFingerprint = card?.dataset.machineHostKeyFingerprint;
    if (!validFingerprint(expectedHostFingerprint)) {
      showToast("The trusted host-key fingerprint is unavailable. Inspect the host key again.", "error", 6000);
      return;
    }
    sshTerminalDialog.querySelector("[data-ssh-terminal-target]").textContent = target;
    sshTerminalDialog.showModal();
    const terminal = new TerminalClass({
      allowProposedApi: false,
      convertEol: true,
      cursorBlink: true,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      fontSize: 13,
      // Remote terminal output must never navigate the administrator's browser.
      // xterm's null/default OSC-8 handler opens links, so provide an inert one.
      linkHandler: {
        activate() {},
        hover() {},
        leave() {},
      },
      scrollback: 5000,
      theme: { background: "#101820", foreground: "#dce6ee", cursor: "#78b7ff" },
      windowOptions: {},
    });
    const fitAddon = new FitAddonClass();
    terminal.loadAddon(fitAddon);
    terminal.open(sshTerminalContainer);
    fitAddon.fit();
    terminal.focus();
    const session = { terminal, fitAddon, socket: null, ready: false, inputDisposable: null, resizeObserver: null, resizeHandler: null };
    activeSshSession = session;
    setTerminalStatus("Authorizing…");
    try {
      const ticket = await requestSshTicket(button.dataset.connectMachine, "terminal");
      if (activeSshSession !== session) return;
      session.socket = openSshGateway(ticket, {
        terminal,
        onControl(control, connection) {
          if (control?.type === "ready" && !session.ready) {
            if (
              !validUuid(control.session_id)
              || !validFingerprint(control.host_key_fingerprint)
              || control.host_key_fingerprint !== expectedHostFingerprint
            ) {
              connection.close(1008, "invalid terminal identity");
              return;
            }
            session.ready = true;
            setTerminalStatus("Connected", "good");
            terminal.focus();
          } else if (control?.type === "exit" && session.ready && Number.isInteger(control.code) && control.code >= 0 && control.code <= 255) {
            terminal.writeln(`\r\n[Remote shell exited with status ${control.code}]`);
            setTerminalStatus("Exited");
            connection.close(1000, "remote shell exited");
          } else if (control?.type === "error") {
            terminal.writeln(`\r\n[Connection error: ${safeSshDiagnostic(control.message || control.code, "unknown error")}]`);
            setTerminalStatus("Connection failed", "bad");
            connection.close(1000, "connection failed");
          } else {
            connection.close(1008, "unexpected terminal response");
          }
        },
        onBinary(bytes, connection) {
          if (!session.ready || bytes.byteLength > 1024 * 1024) {
            connection.close(1008, "invalid terminal data");
            return;
          }
          terminal.write(bytes);
        },
      });
      session.inputDisposable = terminal.onData(data => {
        if (session.ready && session.socket?.readyState === WebSocket.OPEN) {
          const encoded = new TextEncoder().encode(data);
          for (let offset = 0; offset < encoded.byteLength; offset += 16 * 1024) {
            if (session.socket.bufferedAmount > SSH_MAX_BUFFERED_INPUT) {
              terminal.writeln("\r\n[Connection closed: terminal input exceeded the browser buffer limit.]");
              setTerminalStatus("Connection failed", "bad");
              session.socket.close(1008, "terminal input backpressure");
              return;
            }
            session.socket.send(encoded.slice(offset, offset + 16 * 1024));
          }
        }
      });
      session.socket.addEventListener("close", () => {
        session.ready = false;
        if (activeSshSession === session) setTerminalStatus("Disconnected");
      });
      session.socket.addEventListener("error", () => {
        setTerminalStatus("Connection failed", "bad");
      });
      const resizeTerminal = () => {
        if (activeSshSession !== session) return;
        fitAddon.fit();
        if (session.ready && session.socket?.readyState === WebSocket.OPEN) {
          if (session.socket.bufferedAmount > SSH_MAX_BUFFERED_INPUT) return;
          const size = boundedTerminalSize(terminal);
          session.socket.send(JSON.stringify({ type: "resize", cols: size.cols, rows: size.rows }));
        }
      };
      if (globalThis.ResizeObserver) {
        session.resizeObserver = new globalThis.ResizeObserver(resizeTerminal);
        session.resizeObserver.observe(sshTerminalContainer);
      } else {
        session.resizeHandler = resizeTerminal;
        window.addEventListener("resize", resizeTerminal);
      }
    } catch (error) {
      terminal.writeln(`\r\n[${safeSshDiagnostic(error?.message, "The SSH connection could not start.")}]`);
      setTerminalStatus("Connection failed", "bad");
    }
  });
}

for (const button of document.querySelectorAll("[data-ssh-terminal-close], [data-ssh-terminal-disconnect]")) {
  button.addEventListener("click", () => {
    disposeActiveSshSession();
    sshTerminalDialog?.close();
  });
}
sshTerminalDialog?.addEventListener("close", disposeActiveSshSession);

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
