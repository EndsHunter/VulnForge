/**
 * Report finding progression: proposed → mech → disprove → human.
 * Confirmed is human-only. An LLM stand, self-grade, or "survived" count
 * must never use the confirmed tone or a confirmed label.
 *
 * UMD: browser global ReportStateBadges and node require().
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.ReportStateBadges = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const TIPS = {
    proposed:
      "Proposed candidate from a hunt. Mechanical gates have not passed. Not confirmed.",
    proposedDone:
      "Proposed candidate. This finding has moved on. Not a confirm.",
    mechWait:
      "Mechanical gates have not run. A pass becomes needs-human, never confirmed.",
    mechPass:
      "Mechanical gates passed. Not exploit proof and not confirmed.",
    mechReject:
      "Mechanical gates rejected this finding. Stopped here. Not a human decision.",
    mechNa:
      "No mechanical pass is recorded. Confirm, if any, is a separate human action.",
    disproveWait:
      "Dual LLM disprove has not run. A later stand would not confirm. Confirmed is human-only.",
    disprovePending:
      "Dual LLM disprove is still running. Pending is not confirmed. Only an all-slot reject sets rejected (disprove). The harness never auto-confirms.",
    disproveIncomplete:
      "Dual disprove stopped before a verdict. Not a stand and not confirmed. A human still has to accept.",
    disproveStood:
      "LLM disprove could not kill this finding (stand). Stand is not confirmed, not a self-grade, and not exploit proof. Confirmed is human-only — never auto.",
    disproveReject:
      "Every LLM disprove slot returned reject. This is rejected (disprove), not a human confirm. The harness never auto-confirms.",
    disproveOff:
      "LLM disprove did not run. Mech pass waits for a human. Nothing here is confirmed.",
    disproveNa:
      "No dual disprove result is recorded. An LLM self-grade is not confirmed.",
    humanWait:
      "Human review has not happened. Accept is the only path to confirmed. Never auto.",
    needsHuman:
      "Waiting for a human. Accept is the only path to confirmed. An LLM stand cannot confirm.",
    humanAccepted:
      "Confirmed is human-only. An operator explicitly accepted this finding. The harness never auto-confirms. An LLM stand or self-grade is not confirmed.",
    humanRejected:
      "A human rejected this finding. Not an LLM self-grade.",
    superseded:
      "Superseded by a merge into another finding. Not confirmed.",
    unknown:
      "Unrecognized finding state. Not confirmed. Confirmed is human-only and never automatic.",
  };

  const TONES = {
    candidate: true,
    rejected_mech: true,
    rejected_llm: true,
    rejected_human: true,
    needs_human: true,
    confirmed: true,
    superseded: true,
    "step-pass": true,
    "step-stood": true,
    "step-done": true,
    "step-wait": true,
    "step-off": true,
  };

  const KNOWN = {
    "": true,
    candidate: true,
    needs_human: true,
    confirmed: true,
    rejected_mech: true,
    rejected_llm: true,
    rejected_human: true,
    superseded: true,
  };

  function bodyOf(finding) {
    const b = finding && finding.body;
    return b && typeof b === "object" ? b : {};
  }

  function mechOf(finding) {
    const m = bodyOf(finding).validation_mech;
    return m && typeof m === "object" ? m : null;
  }

  function llmOf(finding) {
    const v = bodyOf(finding).validation_llm;
    return v && typeof v === "object" ? v : null;
  }

  function stateOf(finding) {
    return String((finding && finding.state) || "")
      .trim()
      .toLowerCase();
  }

  function llmCounts(llm) {
    if (!llm) return null;
    const verifiers = Array.isArray(llm.verifiers) ? llm.verifiers : null;
    let total = llm.total != null ? Number(llm.total) : verifiers ? verifiers.length : NaN;
    let stood = llm.stood != null ? Number(llm.stood) : NaN;
    if (Number.isNaN(stood) && verifiers) {
      stood = verifiers.filter(
        (x) => String((x && x.verdict) || "").toLowerCase() === "stand"
      ).length;
    }
    if (!Number.isFinite(total) || !Number.isFinite(stood)) return null;
    return { stood: stood, total: total };
  }

  /** All-slot reject only. A zero stand count is not itself a reject. */
  function llmAllReject(llm) {
    if (!llm) return false;
    if (String(llm.aggregate || "").toLowerCase() === "rejected_llm") return true;
    const verifiers = Array.isArray(llm.verifiers) ? llm.verifiers : null;
    if (verifiers && verifiers.length) {
      return verifiers.every(
        (v) => String((v && v.verdict) || "").toLowerCase() === "reject"
      );
    }
    return String(llm.verdict || "").toLowerCase() === "reject";
  }

  function disproveRejected(state, llm) {
    if (state === "rejected_llm") return true;
    return llmAllReject(llm);
  }

  function mechPassed(state, mech, llm) {
    if (state === "rejected_mech") return false;
    if (mech && String(mech.status || "").toLowerCase() === "passed") return true;
    if (state === "rejected_llm") return true;
    if (llm && state !== "candidate" && state !== "") return true;
    return false;
  }

  function step(id, label, tone, title, current) {
    return {
      id: id,
      label: label,
      tone: TONES[tone] ? tone : "step-off",
      title: title,
      current: !!current,
    };
  }

  function fraction(llm) {
    const c = llmCounts(llm);
    if (!c || !(c.total > 0)) return "";
    return " " + c.stood + "/" + c.total;
  }

  function scrub(steps, state) {
    return steps.map(function (s) {
      const out = {
        id: s.id,
        label: s.label,
        tone: s.tone,
        title: s.title,
        current: s.current,
      };
      if (out.tone === "confirmed" && (state !== "confirmed" || out.id !== "human")) {
        out.tone = "step-stood";
      }
      if (state !== "confirmed" && /\bconfirmed\b/i.test(out.label)) {
        out.label = String(out.label).replace(/\bconfirmed\b/gi, "stood");
        if (out.tone === "confirmed") out.tone = "step-stood";
      }
      if (!TONES[out.tone] || (out.tone === "confirmed" && state !== "confirmed")) {
        out.tone = "step-off";
      }
      return out;
    });
  }

  /**
   * Steps for one finding. `tone: "confirmed"` only when state is confirmed
   * and the step is the human accept.
   */
  function findingStateTrail(finding) {
    const state = stateOf(finding);
    const mech = mechOf(finding);
    const llm = llmOf(finding);

    if (state === "superseded") {
      return scrub(
        [step("superseded", "Superseded", "superseded", TIPS.superseded, true)],
        state
      );
    }
    if (!KNOWN[state]) {
      const label = state ? state.replace(/_/g, " ") : "unknown";
      return scrub([step("state", label, "step-off", TIPS.unknown, true)], state);
    }

    const steps = [];
    const atProposed = state === "candidate" || state === "";
    steps.push(
      step(
        "proposed",
        "Proposed",
        atProposed ? "candidate" : "step-done",
        atProposed ? TIPS.proposed : TIPS.proposedDone,
        atProposed
      )
    );

    if (state === "rejected_mech") {
      steps.push(step("mech", "Mech rejected", "rejected_mech", TIPS.mechReject, true));
      return scrub(steps, state);
    }

    const passed = mechPassed(state, mech, llm);
    if (passed) {
      steps.push(step("mech", "Mech pass", "step-pass", TIPS.mechPass, false));
    } else if (atProposed) {
      steps.push(step("mech", "Mech", "step-wait", TIPS.mechWait, false));
    } else {
      steps.push(step("mech", "Mech n/a", "step-off", TIPS.mechNa, false));
    }

    const pendingFlag = !!(mech && mech.pending_llm) && state === "needs_human";
    const status = llm ? String(llm.status || "").toLowerCase() : "";
    const verdict = llm ? String(llm.verdict || "").toLowerCase() : "";
    const agg = llm ? String(llm.aggregate || "").toLowerCase() : "";
    const rejected = disproveRejected(state, llm);
    const incomplete =
      !pendingFlag &&
      !rejected &&
      !!llm &&
      (status === "partial" || verdict === "pending" || agg === "pending");
    const hasResult =
      !!llm &&
      !incomplete &&
      (llmCounts(llm) || llm.label || llm.verdict || llm.aggregate || llm.status);

    if (pendingFlag) {
      steps.push(
        step("disprove", "Disprove pending", "needs_human", TIPS.disprovePending, true)
      );
    } else if (rejected) {
      steps.push(
        step(
          "disprove",
          "Disprove rejected" + fraction(llm),
          "rejected_llm",
          TIPS.disproveReject,
          state === "rejected_llm"
        )
      );
    } else if (incomplete) {
      steps.push(
        step("disprove", "Disprove incomplete", "step-off", TIPS.disproveIncomplete, false)
      );
    } else if (hasResult && (passed || state !== "candidate")) {
      steps.push(
        step(
          "disprove",
          "Disprove stood" + fraction(llm),
          "step-stood",
          TIPS.disproveStood,
          false
        )
      );
    } else if (passed) {
      steps.push(step("disprove", "Disprove off", "step-off", TIPS.disproveOff, false));
    } else if (atProposed) {
      steps.push(step("disprove", "Disprove", "step-wait", TIPS.disproveWait, false));
    } else {
      steps.push(step("disprove", "Disprove n/a", "step-off", TIPS.disproveNa, false));
    }

    if (state === "rejected_llm") {
      return scrub(steps, state);
    }

    if (state === "confirmed") {
      steps.push(step("human", "Human accepted", "confirmed", TIPS.humanAccepted, true));
    } else if (state === "rejected_human") {
      steps.push(
        step("human", "Human rejected", "rejected_human", TIPS.humanRejected, true)
      );
    } else if (state === "needs_human" && !pendingFlag) {
      steps.push(step("human", "Needs human", "needs_human", TIPS.needsHuman, true));
    } else {
      steps.push(step("human", "Human", "step-wait", TIPS.humanWait, false));
    }

    if (!steps.some(function (s) { return s.current; }) && steps.length) {
      steps[steps.length - 1].current = true;
    }
    return scrub(steps, state);
  }

  function escHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function findingStateTrailHtml(finding) {
    const state = stateOf(finding);
    const steps = findingStateTrail(finding);
    const summary = steps
      .map(function (s) {
        return s.label;
      })
      .join(" → ");
    const parts = [];
    steps.forEach(function (s, i) {
      if (i) {
        parts.push('<span class="report-state-arrow" aria-hidden="true">→</span>');
      }
      const cls = ["badge", "report-state-step", s.tone];
      if (s.current) cls.push("is-current");
      parts.push(
        '<span class="' +
          cls.join(" ") +
          '" data-step="' +
          escHtml(s.id) +
          '" title="' +
          escHtml(s.title) +
          '" data-tip="' +
          escHtml(s.title) +
          '" tabindex="0">' +
          escHtml(s.label) +
          "</span>"
      );
    });
    return (
      '<span class="report-state-trail" role="group" aria-label="Finding progression: ' +
      escHtml(summary) +
      '">' +
      parts.join("") +
      "</span>"
    );
  }

  /**
   * Title-cell / detail disprove chip. Tone is an llm-verify class, never confirmed.
   */
  function llmSignal(validationLlm) {
    const llm = validationLlm && typeof validationLlm === "object" ? validationLlm : null;
    if (!llm) return null;
    const counts = llmCounts(llm);
    const verifiers = Array.isArray(llm.verifiers) ? llm.verifiers : null;
    const hasShape =
      counts ||
      llm.label ||
      (verifiers && verifiers.length) ||
      llm.status ||
      llm.verdict ||
      llm.aggregate;
    if (!hasShape) return null;
    const status = String(llm.status || "").toLowerCase();
    const verdict = String(llm.verdict || "").toLowerCase();
    const agg = String(llm.aggregate || "").toLowerCase();
    const allReject = llmAllReject(llm);
    let word = "disprove stood";
    let tone = "llm-verify-mid";
    let title = TIPS.disproveStood;
    if (status === "partial" || verdict === "pending" || agg === "pending") {
      word = "disprove incomplete";
      tone = "llm-verify-mid";
      title = TIPS.disproveIncomplete;
    } else if (allReject) {
      word = "disprove rejected";
      tone = "llm-verify-none";
      title = TIPS.disproveReject;
    } else if (counts && counts.total > 0 && counts.stood >= counts.total) {
      tone = "llm-verify-all";
      title = TIPS.disproveStood;
    }
    return { word: word, tone: tone, title: title, label: llm.label || (counts ? counts.stood + "/" + counts.total : "") };
  }

  return {
    TIPS: TIPS,
    findingStateTrail: findingStateTrail,
    findingStateTrailHtml: findingStateTrailHtml,
    llmSignal: llmSignal,
    llmAllReject: llmAllReject,
  };
});
