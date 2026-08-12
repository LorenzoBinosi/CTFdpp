export { showToast } from "/assets/shared/js/ui.js";

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
