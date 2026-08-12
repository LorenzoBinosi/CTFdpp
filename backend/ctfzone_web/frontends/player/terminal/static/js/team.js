import { apiRequest, idempotencyHeaders } from "/assets/shared/js/api.js";
import { showToast } from "/assets/shared/js/ui.js";

function setBusy(button, busy, label) {
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

async function submitTeamAction(form, path, body, label) {
  if (!form.reportValidity()) return;
  const button = form.querySelector('button[type="submit"]');
  setBusy(button, true, label);
  try {
    await apiRequest(path, {
      method: "POST",
      headers: idempotencyHeaders(),
      body,
    });
    window.location.assign("/team");
  } catch (error) {
    showToast(error.message || "The team action could not be completed.", "error", 6000);
    setBusy(button, false);
  }
}

document.querySelector("[data-team-create]")?.addEventListener("submit", event => {
  event.preventDefault();
  const form = event.currentTarget;
  submitTeamAction(form, "/api/v1/teams/me", { name: form.elements.name.value.trim() }, "Creating…");
});

document.querySelector("[data-team-join]")?.addEventListener("submit", event => {
  event.preventDefault();
  const form = event.currentTarget;
  submitTeamAction(form, "/api/v1/teams/me/join", { code: form.elements.code.value.trim() }, "Joining…");
});

document.querySelector("[data-team-invite-form]")?.addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  setBusy(button, true, "Generating…");
  try {
    const result = await apiRequest("/api/v1/teams/me/members", {
      method: "POST",
      headers: idempotencyHeaders(),
    });
    const code = result.data?.code;
    if (typeof code !== "string" || !code) throw new Error("The API did not return an invite code.");
    const output = document.querySelector("[data-team-invite-code]");
    if (output) output.value = code;
    document.querySelector("[data-team-invite-result]")?.removeAttribute("hidden");
    output?.focus();
    output?.select();
    showToast("Invite generated. It expires in 24 hours.");
  } catch (error) {
    showToast(error.message || "The invite could not be generated.", "error", 6000);
  } finally {
    setBusy(button, false);
  }
});

document.querySelector("[data-team-invite-copy]")?.addEventListener("click", async () => {
  const code = document.querySelector("[data-team-invite-code]")?.value || "";
  if (!code) return;
  try {
    await navigator.clipboard.writeText(code);
    showToast("Invite code copied.");
  } catch (_error) {
    const output = document.querySelector("[data-team-invite-code]");
    output?.focus();
    output?.select();
    showToast("Select and copy the invite code.", "warning");
  }
});
