// SIPBXGO admin: live refresh, copy/reveal buttons, confirmations.
// Plain JS, no dependencies; every page also works without it.
"use strict";

// Live regions: <div data-refresh="/live/..." data-interval="3000">
// is re-fetched and replaced while the tab is visible.
for (const el of document.querySelectorAll("[data-refresh]")) {
  const url = el.dataset.refresh;
  const every = Number(el.dataset.interval) || 3000;
  let busy = false;
  const tick = async () => {
    if (busy || document.hidden) return;
    busy = true;
    try {
      const res = await fetch(url, { credentials: "same-origin", headers: { Accept: "text/html" } });
      if (res.status === 401) { location.reload(); return; }
      if (res.ok) el.innerHTML = await res.text();
    } catch (_) {
      // Network blip; try again next tick.
    } finally {
      busy = false;
    }
  };
  setInterval(tick, every);
  document.addEventListener("visibilitychange", tick);
}

function flashButton(btn, text) {
  const original = btn.dataset.label || btn.textContent;
  btn.dataset.label = original;
  btn.textContent = text;
  btn.classList.add("done");
  setTimeout(() => { btn.textContent = original; btn.classList.remove("done"); }, 1400);
}

document.addEventListener("click", async (e) => {
  const copy = e.target.closest("[data-copy]");
  if (copy) {
    try {
      await navigator.clipboard.writeText(copy.dataset.copy);
      flashButton(copy, "Copied");
    } catch (_) {
      flashButton(copy, "Copy failed");
    }
    return;
  }
  const reveal = e.target.closest("[data-reveal]");
  if (reveal) {
    const target = document.getElementById(reveal.dataset.reveal);
    const shown = reveal.textContent.trim() === "Hide";
    target.textContent = shown ? "••••••••••••" : target.dataset.secret;
    reveal.textContent = shown ? "Show" : "Hide";
  }
});

// <form data-confirm="Are you sure?">
document.addEventListener("submit", (e) => {
  const msg = e.target.dataset.confirm;
  if (msg && !window.confirm(msg)) e.preventDefault();
});

// <select data-autosubmit> submits its form on change.
document.addEventListener("change", (e) => {
  if (e.target.matches("[data-autosubmit]")) e.target.form.requestSubmit();
});
