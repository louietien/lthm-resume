(function () {
  function cssVar(name, fallback) {
    var value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return value || fallback;
  }

  function axisKeys(layout) {
    if (!layout) {
      return ["xaxis", "yaxis"];
    }

    var keys = Object.keys(layout).filter(function (key) {
      return /^xaxis\d*$/.test(key) || /^yaxis\d*$/.test(key);
    });

    if (!keys.length) {
      return ["xaxis", "yaxis"];
    }
    return keys;
  }

  function applyThemeToCharts() {
    if (!window.Plotly || typeof window.Plotly.relayout !== "function") {
      return;
    }

    var ink = cssVar("--ink", "#10212f");
    var muted = cssVar("--muted", ink);
    var panelLine = cssVar("--panel-line", "rgba(90,100,120,0.2)");
    var hoverBg = cssVar("--panel-top", "rgba(255,255,255,0.9)");

    var charts = document.querySelectorAll(".plotly-graph-div");
    charts.forEach(function (node) {
      var update = {
        paper_bgcolor: "rgba(0,0,0,0)",
        plot_bgcolor: "rgba(0,0,0,0)",
        "font.color": ink,
        "title.font.color": ink,
        "legend.font.color": ink,
        "legend.bgcolor": "rgba(0,0,0,0)",
        "hoverlabel.bgcolor": hoverBg,
        "hoverlabel.bordercolor": panelLine,
        "hoverlabel.font.color": ink,
      };

      axisKeys(node.layout).forEach(function (key) {
        update[key + ".linecolor"] = panelLine;
        update[key + ".gridcolor"] = panelLine;
        update[key + ".zerolinecolor"] = panelLine;
        update[key + ".tickfont.color"] = muted;
        update[key + ".title.font.color"] = muted;
      });

      try {
        var relayoutResult = window.Plotly.relayout(node, update);
        if (relayoutResult && typeof relayoutResult.catch === "function") {
          relayoutResult.catch(function () {});
        }
      } catch (error) {
        // Ignore relayout races while htmx swaps chart fragments.
      }
    });
  }

  var scheduled = false;
  function scheduleThemePass() {
    if (scheduled) {
      return;
    }
    scheduled = true;
    window.requestAnimationFrame(function () {
      scheduled = false;
      applyThemeToCharts();
    });
  }

  document.addEventListener("DOMContentLoaded", scheduleThemePass);
  window.addEventListener("load", scheduleThemePass);
  window.addEventListener("stats:themechange", scheduleThemePass);
  document.body.addEventListener("htmx:afterSwap", scheduleThemePass);
  document.body.addEventListener("htmx:afterSettle", scheduleThemePass);
})();
