(function () {
  var root = document.documentElement;

  function mediaTheme() {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function currentTheme() {
    var explicit = root.getAttribute("data-theme");
    if (explicit === "dark" || explicit === "light") {
      return explicit;
    }
    return mediaTheme();
  }

  function emitThemeChange() {
    window.dispatchEvent(
      new CustomEvent("stats:themechange", {
        detail: { theme: currentTheme() },
      })
    );
  }

  function renderToggleLabel(button) {
    if (!button) {
      return;
    }
    var darkLabel = button.getAttribute("data-dark-label") || "Dark mode";
    var lightLabel = button.getAttribute("data-light-label") || "Light mode";
    button.textContent = currentTheme() === "dark" ? lightLabel : darkLabel;
  }

  function setTheme(theme) {
    if (theme !== "dark" && theme !== "light") {
      return;
    }
    root.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
    emitThemeChange();
  }

  function initToggle() {
    var toggle = document.getElementById("theme-toggle");
    if (toggle) {
      renderToggleLabel(toggle);
      toggle.addEventListener("click", function () {
        var next = currentTheme() === "dark" ? "light" : "dark";
        setTheme(next);
        renderToggleLabel(toggle);
      });
    }

    var media = window.matchMedia("(prefers-color-scheme: dark)");
    var syncToSystemTheme = function () {
      if (localStorage.getItem("theme")) {
        return;
      }
      renderToggleLabel(toggle);
      emitThemeChange();
    };

    if (typeof media.addEventListener === "function") {
      media.addEventListener("change", syncToSystemTheme);
    } else if (typeof media.addListener === "function") {
      media.addListener(syncToSystemTheme);
    }
  }

  window.statsTheme = {
    currentTheme: currentTheme,
    setTheme: setTheme,
  };

  document.addEventListener("DOMContentLoaded", function () {
    initToggle();
    emitThemeChange();
  });
})();
