export { showToast } from "/assets/shared/js/ui.js";

const navToggle = document.querySelector("[data-nav-toggle]");
const mainNav = document.querySelector("[data-main-nav]");
const navLinks = mainNav?.querySelector("[data-nav-links]");
const navItems = navLinks ? [...navLinks.querySelectorAll("[data-nav-item]")] : [];
const navOverflow = mainNav?.querySelector("[data-nav-overflow]");
const navOverflowToggle = mainNav?.querySelector("[data-nav-overflow-toggle]");
const navOverflowMenu = mainNav?.querySelector("[data-nav-overflow-menu]");

const closeNavOverflow = (restoreFocus = false) => {
  if (!navOverflowToggle || !navOverflowMenu) return;
  const wasOpen = navOverflowToggle.getAttribute("aria-expanded") === "true";
  navOverflowToggle.setAttribute("aria-expanded", "false");
  navOverflowMenu.hidden = true;
  if (restoreFocus && wasOpen) navOverflowToggle.focus();
};

const updateNavOverflow = () => {
  if (!mainNav || !navLinks || !navOverflow || !navOverflowToggle || !navOverflowMenu) return;

  closeNavOverflow();
  navOverflowMenu.replaceChildren();
  navItems.forEach(item => { item.hidden = false; });
  navOverflow.hidden = true;
  navOverflowToggle.classList.remove("active");

  if (window.matchMedia("(max-width: 860px)").matches || navItems.length === 0) return;

  const gap = Number.parseFloat(window.getComputedStyle(navLinks).columnGap) || 0;
  const widths = navItems.map(item => item.getBoundingClientRect().width);
  const totalWidth = widths.reduce((total, width) => total + width, 0) + gap * Math.max(0, widths.length - 1);
  if (totalWidth <= mainNav.clientWidth + 0.5) return;

  navOverflow.hidden = false;
  const availableWidth = navLinks.clientWidth;
  let visibleWidth = totalWidth;

  for (let index = navItems.length - 1; index >= 0 && visibleWidth > availableWidth + 0.5; index -= 1) {
    const item = navItems[index];
    item.hidden = true;
    const menuItem = item.cloneNode(true);
    menuItem.hidden = false;
    menuItem.removeAttribute("data-nav-item");
    navOverflowMenu.prepend(menuItem);
    visibleWidth -= widths[index];
    if (index > 0) visibleWidth -= gap;
  }

  const hasItems = navOverflowMenu.children.length > 0;
  navOverflow.hidden = !hasItems;
  navOverflowToggle.classList.toggle("active", Boolean(navOverflowMenu.querySelector(".active, [aria-current='page']")));
};

let navOverflowFrame = 0;
const scheduleNavOverflow = () => {
  window.cancelAnimationFrame(navOverflowFrame);
  navOverflowFrame = window.requestAnimationFrame(updateNavOverflow);
};

navOverflowToggle?.addEventListener("click", () => {
  if (!navOverflowMenu) return;
  const open = navOverflowToggle.getAttribute("aria-expanded") !== "true";
  navOverflowToggle.setAttribute("aria-expanded", String(open));
  navOverflowMenu.hidden = !open;
});

document.addEventListener("click", event => {
  if (navOverflow && !navOverflow.contains(event.target)) closeNavOverflow();
});

if (mainNav && "ResizeObserver" in window) {
  new ResizeObserver(scheduleNavOverflow).observe(mainNav);
} else {
  window.addEventListener("resize", scheduleNavOverflow);
}
document.fonts?.ready.then(scheduleNavOverflow);
scheduleNavOverflow();

navToggle?.addEventListener("click", () => {
  const open = mainNav?.classList.toggle("open") || false;
  navToggle.setAttribute("aria-expanded", String(open));
});

document.addEventListener("keydown", event => {
  if (event.key === "Escape" && navOverflowToggle?.getAttribute("aria-expanded") === "true") {
    closeNavOverflow(true);
    return;
  }
  if (event.key === "Escape" && mainNav?.classList.contains("open")) {
    mainNav.classList.remove("open");
    navToggle?.setAttribute("aria-expanded", "false");
    navToggle?.focus();
  }
});
