import { apiRequest } from "/assets/shared/js/api.js";
import { showToast } from "/assets/shared/js/ui.js";

const button = document.querySelector("[data-send-verification]");
const message = document.querySelector("[data-verification-message]");

button?.addEventListener("click", async () => {
  const originalLabel = button.textContent;
  button.disabled = true;
  button.textContent = "Sending…";
  try {
    await apiRequest("/api/v1/users/me/verification-email", { method: "POST" });
    button.textContent = "Email sent";
    if (message) {
      message.textContent = "Check your inbox. The verification link is short-lived and can be used only once.";
    }
    showToast("Verification email sent.");
  } catch (error) {
    button.disabled = false;
    button.textContent = originalLabel;
    showToast(error.message || "The verification email could not be sent.", "error", 5500);
  }
});
