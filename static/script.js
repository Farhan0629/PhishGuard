/* =========================================================================
   PHISHGUARD // TERMINAL CONTROLLER
   - Wires the input to POST /api/check
   - Drives the ASCII meter, LED, glitch reveal, type-on
   - Keeps the same JSON contract as before
   ========================================================================= */
(() => {
  // ---- DOM ----
  const $ = (id) => document.getElementById(id);
  const form        = $("check-form");
  const input       = $("url-input");
  const btn         = $("check-btn");
  const result      = $("result");
  const led         = $("led");
  const label       = $("indicator");
  const tier        = $("tier");
  const scoreEl     = $("score");
  const barAscii    = $("bar-ascii");
  const reasonEl    = $("reason");
  const metaEl      = $("meta");

  // ---- ASCII meter ----
  // 24 cells wide, 8 levels of fill per cell — same shape on every render.
  const BAR_CELLS = 24;
  function renderBar(pct) {
    const filled = Math.round((pct / 100) * BAR_CELLS);
    const out = ["["];
    for (let i = 0; i < BAR_CELLS; i++) {
      out.push(i < filled ? `<span class="bar-lit">█</span>` : "░");
    }
    out.push("]");
    barAscii.innerHTML = out.join("");
  }

  // ---- Glitch number reveal ----
  // Cycles the displayed score through random hex glyphs before settling.
  function glitchNumber(target, ms = 380) {
    const glyphs = "01░▒▓█▌▐";
    const t0 = performance.now();
    function tick(now) {
      const t = (now - t0) / ms;
      if (t >= 1) { scoreEl.textContent = String(target); return; }
      const r = Math.random();
      scoreEl.textContent = r < 0.4
        ? String(target)
        : glyphs[Math.floor(Math.random() * glyphs.length)].repeat(String(target).length);
      requestAnimationFrame(tick);
    }
    scoreEl.textContent = "??";
    requestAnimationFrame(tick);
  }

  // ---- Type-on for the reason text ----
  function typeOn(el, text, speed = 14) {
    el.classList.add("typing");
    el.textContent = "";
    let i = 0;
    const step = () => {
      if (i >= text.length) { el.classList.remove("typing"); return; }
      el.textContent += text.charAt(i++);
      setTimeout(step, speed);
    };
    step();
  }

  // ---- Render ----
  const TIER_LABEL = {
    safe:        "[ TIER-0 :: CLEAN   ]",
    likely_safe: "[ TIER-1 :: BENIGN  ]",
    suspicious:  "[ TIER-2 :: CAUTION ]",
    fake:        "[ TIER-3 :: MALICIOUS ]",
  };
  const INDICATOR_LABEL_FALLBACK = {
    safe: "SAFE", likely_safe: "LIKELY SAFE", suspicious: "SUSPICIOUS", fake: "LIKELY FAKE",
  };

  function renderFlags(flags) {
    metaEl.innerHTML = "";
    if (!flags || flags.length === 0) {
      const s = document.createElement("span");
      s.className = "flag flag-empty";
      s.textContent = "no_flags";
      metaEl.appendChild(s);
      return;
    }
    flags.forEach(f => {
      const s = document.createElement("span");
      s.className = "flag";
      s.textContent = f.replace(/_/g, " ");
      metaEl.appendChild(s);
    });
  }

  function render(data) {
    // Result panel state
    result.classList.remove("hidden");
    result.dataset.indicator = data.indicator;

    // LED + label
    const ind = data.indicator;
    label.textContent = (data.label || INDICATOR_LABEL_FALLBACK[ind] || ind).toUpperCase();
    tier.textContent  = TIER_LABEL[ind] || "[ UNKNOWN ]";

    // Score
    const score = Math.max(0, Math.min(100, data.score | 0));
    renderBar(score);
    glitchNumber(score);

    // Reason (type-on, with the cursor shown while typing)
    typeOn(reasonEl, data.reason || "—");

    // Flags
    renderFlags(data.flags);
  }

  // ---- Network ----
  async function checkUrl(url) {
    btn.disabled = true;
    const original = btn.innerHTML;
    btn.innerHTML = '<span class="btn-bracket">[</span>...<span class="btn-bracket">]</span>';
    try {
      const r = await fetch("/api/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const data = await r.json();
      render(data);
    } catch (err) {
      result.classList.remove("hidden");
      result.dataset.indicator = "fake";
      label.textContent  = "ERROR";
      tier.textContent   = "[ TIER-X :: COMM-FAULT ]";
      renderBar(0);
      scoreEl.textContent = "ERR";
      typeOn(reasonEl, "could not reach the analyzer: " + err.message);
      metaEl.innerHTML = "";
      const s = document.createElement("span");
      s.className = "flag flag-empty";
      s.textContent = "transport_error";
      metaEl.appendChild(s);
    } finally {
      btn.disabled = false;
      btn.innerHTML = original;
    }
  }

  // ---- Wire ----
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const v = input.value.trim();
    if (v) { checkUrl(v); }
  });

  document.querySelectorAll(".ex").forEach(b => {
    b.addEventListener("click", () => {
      input.value = b.dataset.url;
      checkUrl(b.dataset.url);
    });
  });

  // Initial paint: zero everything
  renderBar(0);
  scoreEl.textContent = "--";
})();
