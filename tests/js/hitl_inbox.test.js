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

describe("accept while pending_llm", () => {
  it("exports the same Accept block copy as Report", () => {
    assert.equal(
      hitl.ACCEPT_PENDING_COPY,
      "Dual disprove still running — Accept after it settles, or Reject now."
    );
    assert.equal(hitl.acceptBlocked({ pending_llm: true }), true);
    assert.equal(hitl.acceptBlocked({ pending_llm: false }), false);
    assert.equal(hitl.acceptBlocked({}), false);
  });

  it("disables Accept and keeps Reject while pending_llm", () => {
    const html = hitl.renderInbox({
      items: [{ ...findingItem, pending_llm: true }],
    });
    assert.match(html, /Dual disprove still running — Accept after it settles, or Reject now\./);
    assert.match(html, /class="controls-hint hitl-accept-pending"/);
    const accept = html.match(/<button[^>]*data-value="approved"[^>]*>/);
    const reject = html.match(/<button[^>]*data-value="changes-requested"[^>]*>/);
    assert.ok(accept);
    assert.ok(reject);
    assert.match(accept[0], /disabled/);
    assert.match(accept[0], /aria-disabled="true"/);
    assert.match(accept[0], /data-accept-blocked="1"/);
    assert.doesNotMatch(reject[0], /disabled/);
    assert.match(html, /Open in Report/);
  });

  it("leaves Accept enabled when pending_llm is false or absent", () => {
    for (const item of [{ ...findingItem, pending_llm: false }, findingItem]) {
      const html = hitl.renderInbox({ items: [item] });
      const accept = html.match(/<button[^>]*data-value="approved"[^>]*>/);
      assert.ok(accept);
      assert.doesNotMatch(accept[0], /disabled/);
      assert.doesNotMatch(html, /hitl-accept-pending/);
    }
  });
});
