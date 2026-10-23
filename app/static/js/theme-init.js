// Runs before first paint. A saved choice wins; otherwise CSS follows the system.
(function () {
  try {
    var t = localStorage.getItem("tv-theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) { /* storage blocked: follow the system setting */ }
})();
