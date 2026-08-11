import { ApiError, apiRequest, idempotencyHeaders } from "./api.js";
import { showToast } from "./app.js";

const board = document.querySelector("[data-challenge-board]");
const rowsContainer = document.querySelector("[data-challenge-rows]");
const panel = document.querySelector("[data-challenge-panel]");
const search = document.querySelector("[data-challenge-search]");
const empty = document.querySelector("[data-filter-empty]");
const visibleCount = document.querySelector("[data-visible-count]");
const filterDrawer = document.querySelector("[data-filter-drawer]");
let activeCategory = "all";
const activeFilters = new Set();
let panelRequest = null;
let transitionToken = 0;
let countdownTimer = null;

function challengeRows() {
  return [...document.querySelectorAll("[data-challenge-id]")];
}

function applyFilters() {
  const term = (search?.value || "").trim().toLocaleLowerCase();
  let count = 0;
  for (const row of challengeRows()) {
    const categoryMatch = activeCategory === "all" || row.dataset.category === activeCategory;
    const searchMatch = !term || `${row.dataset.name} ${row.dataset.category} ${row.dataset.tags}`.includes(term);
    const unsolvedMatch = !activeFilters.has("unsolved") || row.dataset.solved !== "true";
    const instanceMatch = !activeFilters.has("instance") || row.dataset.instance === "true";
    const easyMatch = !activeFilters.has("easy") || row.dataset.tags.split(" ").includes("easy");
    const visible = categoryMatch && searchMatch && unsolvedMatch && instanceMatch && easyMatch;
    row.hidden = !visible;
    if (visible) count += 1;
  }
  if (empty) empty.hidden = count !== 0;
  if (visibleCount) visibleCount.textContent = String(count);
}

document.querySelectorAll("[data-category]").forEach(button => {
  if (!button.classList.contains("category-link")) return;
  button.addEventListener("click", () => {
    activeCategory = button.dataset.category;
    document.querySelectorAll(".category-link").forEach(item => item.classList.toggle("active", item === button));
    applyFilters();
    filterDrawer?.classList.remove("open");
  });
});

document.querySelectorAll("[data-filter-toggle]").forEach(button => {
  button.addEventListener("click", () => {
    const filter = button.dataset.filterToggle;
    if (activeFilters.has(filter)) activeFilters.delete(filter);
    else activeFilters.add(filter);
    button.classList.toggle("active", activeFilters.has(filter));
    applyFilters();
  });
});

search?.addEventListener("input", applyFilters);
document.addEventListener("keydown", event => {
  const target = event.target;
  if (event.key === "/" && !(target instanceof HTMLInputElement) && !(target instanceof HTMLTextAreaElement)) {
    event.preventDefault();
    search?.focus();
  }
  if (event.key === "Escape") {
    filterDrawer?.classList.remove("open");
    closePanel();
  }
});

document.querySelector("[data-filter-drawer-toggle]")?.addEventListener("click", () => {
  filterDrawer?.classList.toggle("open");
});

function selectRow(challengeId) {
  challengeRows().forEach(row => row.classList.toggle("selected", row.dataset.challengeId === String(challengeId)));
}

async function loadPanel(challengeId, { updateHistory = false, open = true } = {}) {
  if (!panel) return false;
  panelRequest?.abort();
  panelRequest = new AbortController();
  panel.classList.add("loading");
  selectRow(challengeId);
  try {
    const response = await fetch(`/bff/fragments/challenges/${encodeURIComponent(challengeId)}`, {
      signal: panelRequest.signal,
      headers: { accept: "text/html" },
      credentials: "same-origin",
    });
    const html = await response.text();
    panel.innerHTML = html;
    hydratePanel();
    if (open) panel.classList.add("open");
    if (updateHistory) {
      const url = new URL(window.location.href);
      url.searchParams.set("challenge", challengeId);
      history.pushState({ challengeId }, "", url);
    }
    return response.ok;
  } catch (error) {
    if (error.name !== "AbortError") showToast("Unable to load challenge details.", "error");
    return false;
  } finally {
    panel.classList.remove("loading");
  }
}

rowsContainer?.addEventListener("click", event => {
  const row = event.target.closest("[data-challenge-id]");
  if (!row) return;
  event.preventDefault();
  loadPanel(row.dataset.challengeId, { updateHistory: true });
});

function closePanel() {
  panel?.classList.remove("open");
  filterDrawer?.classList.remove("open");
}

document.querySelector("[data-panel-backdrop]")?.addEventListener("click", closePanel);

function formatRemaining(milliseconds) {
  if (milliseconds <= 0) return "00:00";
  const seconds = Math.floor(milliseconds / 1000);
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainder = seconds % 60;
  return hours > 0
    ? `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(remainder).padStart(2, "0")}`
    : `${String(minutes).padStart(2, "0")}:${String(remainder).padStart(2, "0")}`;
}

function startCountdown() {
  window.clearInterval(countdownTimer);
  const clocks = [...panel.querySelectorAll("[data-expires-at]")];
  if (!clocks.length) return;
  const update = () => {
    for (const clock of clocks) {
      const expires = Date.parse(clock.dataset.expiresAt);
      clock.textContent = Number.isFinite(expires) ? formatRemaining(expires - Date.now()) : "--:--";
    }
  };
  update();
  countdownTimer = window.setInterval(update, 1000);
}

async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
    showToast("Copied to clipboard.");
  } catch (_error) {
    showToast("Clipboard access was denied.", "error");
  }
}

async function runtimeAction(button) {
  const action = button.dataset.runtimeAction;
  const challengeId = button.dataset.challengeId || panel.querySelector("[data-current-challenge]")?.dataset.currentChallenge;
  const instanceId = button.dataset.instanceId;
  let path;
  let method = "POST";
  let body = {};
  if (action === "start") path = `/api/v1/challenges/${challengeId}/instance`;
  else if (action === "stop") {
    path = `/api/v1/challenges/${challengeId}/instance`;
    method = "DELETE";
  } else if (action === "extend") {
    path = `/api/v1/instances/${instanceId}/extend`;
    body = { additional_seconds: 900 };
  } else return;

  button.disabled = true;
  const token = ++transitionToken;
  try {
    await apiRequest(path, { method, body, headers: idempotencyHeaders() });
    showToast(action === "start" ? "Instance launch requested." : action === "stop" ? "Instance shutdown requested." : "Instance extended by 15 minutes.");
    await loadPanel(challengeId, { open: true });
    if (action !== "extend") await reconcileTransition(challengeId, token);
  } catch (error) {
    showToast(error instanceof ApiError ? error.message : "Runtime request failed.", "error", 5000);
    button.disabled = false;
  }
}

async function reconcileTransition(challengeId, token) {
  // This is bounded transition observation, not permanent status polling.
  for (const delay of [700, 1400, 2800, 5000, 8000]) {
    await new Promise(resolve => window.setTimeout(resolve, delay));
    if (token !== transitionToken || document.hidden) return;
    await loadPanel(challengeId, { open: true });
    const state = panel.querySelector("[data-runtime-state]")?.dataset.runtimeState;
    if (!state || ["ready", "failed", "expired", "terminated"].includes(state)) return;
  }
  showToast("The controller is still working. Reopen the challenge to refresh status.", "warning", 5000);
}

async function submitFlag(form) {
  const input = form.elements.submission;
  const challengeId = form.dataset.challengeId;
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    const { data } = await apiRequest("/api/v1/challenges/attempt", {
      method: "POST",
      body: { challenge_id: Number(challengeId), submission: input.value },
    });
    const status = data?.status;
    const message = data?.message || (status === "correct" ? "Correct!" : "Submission received.");
    const tone = status === "correct" || status === "already_solved" ? "success" : status === "partial" ? "warning" : "error";
    showToast(message, tone, 4500);
    if (["correct", "already_solved"].includes(status)) {
      const row = document.querySelector(`[data-challenge-id="${CSS.escape(String(challengeId))}"]`);
      row?.classList.add("solved");
      if (row) row.dataset.solved = "true";
      input.value = "";
      await loadPanel(challengeId, { open: true });
    }
  } catch (error) {
    const authenticationRequired =
      error instanceof ApiError &&
      (error.status === 401 || error.payload?.data?.status === "authentication_required");
    if (authenticationRequired) {
      window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname + window.location.search)}`);
      return;
    }
    showToast(error instanceof ApiError ? error.message : "Flag submission failed.", "error", 5000);
  } finally {
    button.disabled = false;
  }
}

async function unlockHint(button) {
  const cost = Number(button.dataset.hintCost || 0);
  if (!window.confirm(cost > 0 ? `Spend ${cost} points to unlock this hint?` : "Unlock this hint?")) return;
  const challengeId = panel.querySelector("[data-current-challenge]")?.dataset.currentChallenge;
  button.disabled = true;
  try {
    await apiRequest("/api/v1/unlocks", {
      method: "POST",
      body: { target: Number(button.dataset.unlockHint), type: "hints" },
    });
    showToast(cost > 0 ? `Hint unlocked for ${cost} points.` : "Hint unlocked.");
    await loadPanel(challengeId, { open: true });
  } catch (error) {
    showToast(error instanceof ApiError ? error.message : "Unable to unlock hint.", "error");
    button.disabled = false;
  }
}

panel?.addEventListener("click", event => {
  const close = event.target.closest("[data-close-panel]");
  if (close) return closePanel();
  const copy = event.target.closest("[data-copy]");
  if (copy) return copyText(copy.dataset.copy);
  const runtime = event.target.closest("[data-runtime-action]");
  if (runtime) return runtimeAction(runtime);
  const hint = event.target.closest("[data-unlock-hint]");
  if (hint) return unlockHint(hint);
});

panel?.addEventListener("submit", event => {
  const form = event.target.closest("[data-flag-form]");
  if (!form) return;
  event.preventDefault();
  submitFlag(form);
});

function hydratePanel() {
  startCountdown();
}

window.addEventListener("popstate", event => {
  const challengeId = event.state?.challengeId || new URL(window.location.href).searchParams.get("challenge");
  if (challengeId) loadPanel(challengeId, { open: true });
  else closePanel();
});

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) startCountdown();
});

hydratePanel();
applyFilters();
