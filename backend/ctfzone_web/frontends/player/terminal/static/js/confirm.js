const tokenInput = document.querySelector("[data-confirm-token]");
const submitButton = document.querySelector("[data-confirm-submit]");
const errorMessage = document.querySelector("[data-confirm-error]");

let token = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : "";
if (window.location.hash) {
  window.history.replaceState(
    window.history.state,
    "",
    window.location.pathname,
  );
}

try {
  token = decodeURIComponent(token);
} catch (_error) {
  token = "";
}

const usable = Boolean(token) && token.length <= 4096 && !/[\u0000-\u001f\u007f]/u.test(token);
if (usable && tokenInput && submitButton) {
  tokenInput.value = token;
  tokenInput.disabled = false;
  submitButton.disabled = false;
  submitButton.focus({ preventScroll: true });
} else {
  errorMessage?.removeAttribute("hidden");
}

token = "";
