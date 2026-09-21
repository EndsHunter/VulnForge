"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const hitl = require(path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "hitl_inbox.js"));

const findingItem = {
  id: "finding-3",
  schema: "vulnforge/hitl-report@1",
  status: "awaiting-review",
  title: "SQL injection in search_users",
  source: { kind: "finding", id: "3", state: "needs_human" },
  blocks: [
    { type: "prose", markdown: "**State:** `needs_human`" },
    { type: "approval", id: "finding-3-review", prompt: "Accept this finding?" },
    { type: "ask", id: "finding-3-notes", prompt: "Notes", mode: "text" },
  ],
  responses: {},
};

describe("inbox contract helpers", () => {
  it("lists only awaiting-review items", () => {
    const items = hitl.inboxItems({
      items: [findingItem, { id: "done-1", status: "done", blocks: [] }],
    });
    assert.equal(items.length, 1);
    assert.equal(items[0].id, "finding-3");
  });

  it("treats a missing response as unanswered", () => {
    const open = hitl.unansweredBlocks(findingItem, {});
    assert.deepEqual(open.map((b) => b.id), ["finding-3-review", "finding-3-notes"]);
    assert.equal(hitl.responseFor({}, "finding-3-review"), null);
    assert.equal(hitl.responseFor({ "finding-3-review": { value: "" } }, "finding-3-review"), null);
  });

  it("renders the durable inbox without inventing an approval", () => {
    const html = hitl.renderInbox({ items: [findingItem] });
    assert.match(html, /SQL injection in search_users/);
    assert.match(html, /awaiting-review/);
    assert.match(html, /vulnforge\/hitl-report@1/);
    assert.match(html, /data-value="approved"/);
    assert.match(html, /Accept \(confirmed\)/);
    assert.doesNotMatch(html, /Recorded answer/);
    assert.match(html, /state needs_human/);
  });

  it("shows a stored answer and escapes markup", () => {
    const html = hitl.renderInbox({
      items: [
        {
          ...findingItem,
          title: "<script>alert(1)</script>",
          responses: {
            "finding-3-notes": {
              block: "finding-3-notes",
              value: "checked <b>manually</b>",
              note: "",
              at: "2026-09-21T00:00:00Z",
            },
          },
        },
      ],
    });
    assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.match(html, /Recorded answer/);
    assert.match(html, /checked &lt;b&gt;manually&lt;\/b&gt;/);
    const open = hitl.unansweredBlocks(findingItem, {
      "finding-3-notes": { value: "checked" },
    });
    assert.deepEqual(open.map((b) => b.id), ["finding-3-review"]);
  });

  it("renders an explicit decision packet and an empty inbox", () => {
    const html = hitl.renderInbox({
      items: [
        {
          id: "gate-export",
          schema: "vulnforge/hitl-report@1",
          status: "awaiting-review",
          title: "Export gate",
          source: { kind: "gate", id: "gate-export" },
          blocks: [
            {
              type: "decision",
              id: "gate-export-choice",
              prompt: "Include transcripts?",
              a: { tag: "include", title: "Include" },
              b: { tag: "omit", title: "Omit" },
            },
          ],
          responses: {},
        },
      ],
    });
    assert.match(html, /data-value="omit"/);
    assert.match(html, /Include transcripts\?/);
    assert.equal(hitl.renderInbox({ items: [] }), '<p class="controls-hint hitl-empty">No items awaiting review.</p>');
  });
});
