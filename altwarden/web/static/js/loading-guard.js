// A plain script, so it still runs when a blocker or an old browser stops the page's module from loading.
setTimeout(() => {
  if (window.pageStarted) return;  // the page's own script is running, and only the server is slow
  const waiting = [...document.querySelectorAll("p")].find((node) => node.textContent === "Loading\u2026");
  if (!waiting) return;
  waiting.textContent = "This page didn't load. Turn off anything blocking scripts on this site, then ";
  const again = document.createElement("a");
  again.href = location.href;
  again.textContent = "reload it";
  waiting.append(again, ".");
}, 15000);
