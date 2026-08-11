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

const navToggle = document.querySelector("[data-nav-toggle]");
const mainNav = document.querySelector("[data-main-nav]");
navToggle?.addEventListener("click", () => {
  const open = mainNav?.classList.toggle("open") || false;
  navToggle.setAttribute("aria-expanded", String(open));
});

document.addEventListener("keydown", event => {
  if (event.key === "Escape" && mainNav?.classList.contains("open")) {
    mainNav.classList.remove("open");
    navToggle?.setAttribute("aria-expanded", "false");
    navToggle?.focus();
  }
});
