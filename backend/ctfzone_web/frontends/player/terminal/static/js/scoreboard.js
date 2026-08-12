const search = document.querySelector("[data-score-search]");
const rows = [...document.querySelectorAll("[data-score-name]")];

search?.addEventListener("input", () => {
  const term = search.value.trim().toLocaleLowerCase();
  for (const row of rows) row.hidden = Boolean(term) && !row.dataset.scoreName.includes(term);
});
