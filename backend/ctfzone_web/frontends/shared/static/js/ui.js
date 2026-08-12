const toastRegion = document.querySelector("[data-toast-region]");

export function showToast(message, tone = "success", timeout = 3500) {
  if (!toastRegion || !message) return;
  const toast = document.createElement("div");
  toast.className = `toast ${tone}`;
  toast.textContent = message;
  toastRegion.append(toast);
  window.setTimeout(() => {
    toast.classList.add("leaving");
    window.setTimeout(() => toast.remove(), 180);
  }, timeout);
}
