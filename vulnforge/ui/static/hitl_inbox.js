/**
 * Durable HITL inbox renderer.
 * Schema vulnforge/hitl-report@1. Missing responses are unanswered.
 * UMD/CommonJS — browser script tag and node --test.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.VulnForgeHitl = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var SCHEMA = "vulnforge/hitl-report@1";
  var INTERACTIVE = { ask: 1, decision: 1, approval: 1 };

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function interactiveBlocks(packet) {
    var blocks = (packet && packet.blocks) || [];
    return blocks.filter(function (b) {
      return b && INTERACTIVE[b.type];
    });
  }

  function responseFor(responses, blockId) {
    if (!responses || !blockId) return null;
    var row = responses[blockId];
    if (!row || row.value == null || String(row.value) === "") return null;
    return row;
  }

  /** Blocks with no stored answer. Absence is not approval. */
  function unansweredBlocks(packet, responses) {
    return interactiveBlocks(packet).filter(function (b) {
      return !responseFor(responses, b.id);
    });
  }

  function inboxItems(payload) {
    var items = payload && Array.isArray(payload.items) ? payload.items : [];
    return items.filter(function (item) {
      return item && item.status === "awaiting-review";
    });
  }

  function proseText(item) {
    var blocks = (item && item.blocks) || [];
    for (var i = 0; i < blocks.length; i++) {
      if (blocks[i] && blocks[i].type === "prose" && blocks[i].markdown) {
        return String(blocks[i].markdown);
      }
    }
    return "";
  }

  function sourceLine(item) {
    var src = (item && item.source) || {};
    if (src.kind === "finding") {
      var state = src.state || "needs_human";
      return (
        "Finding #" +
        esc(src.id) +
        " · state " +
        esc(state) +
        " · confirmed only after Accept"
      );
    }
    var kind = src.kind || item.kind || "packet";
    return esc(kind) + " · explicit HITL packet";
  }

  function savedLine(row) {
    if (!row) return "";
    var note = row.note ? " · " + row.note : "";
    return (
      '<p class="controls-hint hitl-saved">Recorded answer: <span class="mono">' +
      esc(row.value) +
      "</span>" +
      (row.at ? " · " + esc(row.at) : "") +
      esc(note) +
      ". A recorded answer is not confirmation unless Accept was the explicit review.</p>"
    );
  }

  function noteField(reportId, blockId) {
    return (
      '<label class="hitl-field"><span class="label-text">Note</span>' +
      '<textarea class="hitl-note" data-hitl-note rows="2" ' +
      'data-report="' + esc(reportId) + '" data-block="' + esc(blockId) + '" ' +
      'placeholder="Optional note stored with this answer"></textarea></label>'
    );
  }

  function btn(reportId, blockId, value, label, extraClass) {
    return (
      '<button type="button" class="btn ' + (extraClass || "") + '" ' +
      'data-hitl-action="respond" data-report="' + esc(reportId) + '" ' +
      'data-block="' + esc(blockId) + '" data-value="' + esc(value) + '">' +
      esc(label) +
      "</button>"
    );
  }

  function blockHtml(item, block) {
    var reportId = item.id;
    var responses = item.responses || {};
    var saved = responseFor(responses, block.id);
    var actions = "";
    if (block.type === "approval") {
      actions =
        '<div class="hitl-item-actions">' +
        btn(reportId, block.id, "approved", "Accept (confirmed)", "btn-good") +
        btn(reportId, block.id, "changes-requested", "Reject", "btn-bad") +
        (item.source && item.source.kind === "finding"
          ? '<button type="button" class="btn" data-hitl-action="open" data-finding="' +
            esc(item.source.id) +
            '">Open in Report</button>'
          : "") +
        "</div>";
      return (
        '<div class="hitl-block" data-hitl-block="' + esc(block.id) + '">' +
        '<p class="hitl-prompt">' + esc(block.prompt || "") + "</p>" +
        savedLine(saved) +
        noteField(reportId, block.id) +
        actions +
        "</div>"
      );
    }
    if (block.type === "decision") {
      var a = block.a || {};
      var b = block.b || {};
      actions =
        '<div class="hitl-item-actions">' +
        btn(reportId, block.id, a.tag || "", a.title || a.tag || "A", "btn-primary") +
        btn(reportId, block.id, b.tag || "", b.title || b.tag || "B", "") +
        "</div>";
      return (
        '<div class="hitl-block" data-hitl-block="' + esc(block.id) + '">' +
        '<p class="hitl-prompt">' + esc(block.prompt || "") + "</p>" +
        savedLine(saved) +
        noteField(reportId, block.id) +
        actions +
        "</div>"
      );
    }
    if (block.type === "ask" && block.mode === "yesno") {
      actions =
        '<div class="hitl-item-actions">' +
        btn(reportId, block.id, "yes", "Yes", "btn-primary") +
        btn(reportId, block.id, "no", "No", "") +
        "</div>";
    } else if (block.type === "ask" && block.mode === "choice") {
      var opts = Array.isArray(block.options) ? block.options : [];
      actions =
        '<div class="hitl-item-actions">' +
        opts
          .map(function (opt) {
            var value = typeof opt === "string" ? opt : (opt && (opt.value || opt.id || opt.label || opt.text)) || "";
            var label = typeof opt === "string" ? opt : (opt && (opt.label || opt.text || opt.value || opt.id)) || value;
            return btn(reportId, block.id, value, label, "");
          })
          .join("") +
        "</div>";
    } else {
      actions =
        '<label class="hitl-field"><span class="label-text">Answer</span>' +
        '<textarea class="hitl-text" data-hitl-text rows="2" placeholder="Your answer"></textarea></label>' +
        '<div class="hitl-item-actions">' +
        '<button type="button" class="btn btn-primary" data-hitl-action="respond" ' +
        'data-report="' + esc(reportId) + '" data-block="' + esc(block.id) + '" ' +
        'data-value-from="text">Save answer</button></div>';
    }
    return (
      '<div class="hitl-block" data-hitl-block="' + esc(block.id) + '">' +
      '<p class="hitl-prompt">' + esc(block.prompt || "") + "</p>" +
      savedLine(saved) +
      actions +
      "</div>"
    );
  }

  function renderInbox(payload) {
    var items = inboxItems(payload);
    if (!items.length) {
      return '<p class="controls-hint hitl-empty">No items awaiting review.</p>';
    }
    return items
      .map(function (item) {
        var prose = proseText(item);
        var blocks = interactiveBlocks(item);
        return (
          '<article class="hitl-item" data-hitl-item="' + esc(item.id) + '">' +
          '<div class="hitl-item-head">' +
          "<h3 class=\"hitl-item-title\">" + esc(item.title || item.id) + "</h3>" +
          '<span class="badge warn">awaiting-review</span>' +
          '<span class="mono hitl-schema">' + esc(item.schema || SCHEMA) + "</span>" +
          "</div>" +
          '<p class="controls-hint hitl-meta">' + sourceLine(item) + "</p>" +
          (prose ? '<pre class="hitl-prose">' + esc(prose) + "</pre>" : "") +
          blocks.map(function (b) { return blockHtml(item, b); }).join("") +
          "</article>"
        );
      })
      .join("");
  }

  var handlers = {};
  var roots = ["hitl-inbox", "hitl-inbox-report"];

  function noteFor(button) {
    var block = button.closest("[data-hitl-block]");
    var area = block && block.querySelector("[data-hitl-note]");
    return area ? area.value : "";
  }

  function onClick(ev) {
    var button = ev.target && ev.target.closest ? ev.target.closest("[data-hitl-action]") : null;
    if (!button) return;
    var action = button.getAttribute("data-hitl-action");
    if (action === "open") {
      if (handlers.onOpenFinding) handlers.onOpenFinding(button.getAttribute("data-finding"));
      return;
    }
    if (action !== "respond") return;
    var blockEl = button.closest("[data-hitl-block]");
    var value = button.getAttribute("data-value") || "";
    if (button.getAttribute("data-value-from") === "text") {
      var text = blockEl && blockEl.querySelector("[data-hitl-text]");
      value = text ? String(text.value || "").trim() : "";
      if (!value) {
        if (handlers.onError) handlers.onError("Enter a response before saving");
        return;
      }
    }
    if (!value) {
      if (handlers.onError) handlers.onError("Missing response value");
      return;
    }
    if (handlers.onRespond) {
      handlers.onRespond({
        reportId: button.getAttribute("data-report"),
        blockId: button.getAttribute("data-block"),
        value: value,
        note: noteFor(button),
        button: button,
      });
    }
  }

  function mountAll(payload, nextHandlers) {
    handlers = nextHandlers || {};
    var html = renderInbox(payload);
    if (typeof document === "undefined") return html;
    roots.forEach(function (id) {
      var root = document.getElementById(id);
      if (!root) return;
      var body = root.querySelector("[data-hitl-body]");
      if (body) body.innerHTML = html;
      if (!root.dataset.hitlBound) {
        root.dataset.hitlBound = "1";
        root.addEventListener("click", onClick);
      }
    });
    return html;
  }

  function mountError(message) {
    var html = '<p class="hitl-error">' + esc(message || "Inbox failed to load") + "</p>";
    if (typeof document === "undefined") return html;
    roots.forEach(function (id) {
      var root = document.getElementById(id);
      if (!root) return;
      var body = root.querySelector("[data-hitl-body]");
      if (body) body.innerHTML = html;
    });
    return html;
  }

  return {
    SCHEMA: SCHEMA,
    esc: esc,
    interactiveBlocks: interactiveBlocks,
    responseFor: responseFor,
    unansweredBlocks: unansweredBlocks,
    inboxItems: inboxItems,
    renderInbox: renderInbox,
    mountAll: mountAll,
    mountError: mountError,
  };
});
