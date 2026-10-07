"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const CHAT = fs.readFileSync(
  path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "chat.js"),
  "utf8"
);

function match(el, sel) {
  if (!el || el.tagName === "#TEXT") return false;
  if (sel.charAt(0) === "#" && sel.indexOf(" ") === -1 && sel.indexOf(".") === -1) {
    return el.id === sel.slice(1);
  }
  if (sel.charAt(0) === "[" && sel.charAt(sel.length - 1) === "]" && sel.indexOf(" ") === -1) {
    const body = sel.slice(1, -1);
    const eq = body.indexOf("=");
    if (eq === -1) return Object.prototype.hasOwnProperty.call(el.attrs, body);
    let v = body.slice(eq + 1);
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    return el.attrs[body.slice(0, eq)] === v;
  }
  let tag = null;
  let classes = [];
  if (sel.charAt(0) === ".") classes = sel.split(".").filter(Boolean);
  else {
    const dot = sel.indexOf(".");
    if (dot === -1) tag = sel.toUpperCase();
    else {
      tag = sel.slice(0, dot).toUpperCase();
      classes = sel.slice(dot + 1).split(".").filter(Boolean);
    }
  }
  if (tag && el.tagName !== tag) return false;
  for (const c of classes) if (!el._classes.has(c)) return false;
  return !!(tag || classes.length);
}

function walk(el, fn) {
  for (const child of el.children || []) {
    fn(child);
    walk(child, fn);
  }
}

function queryAll(root, sel) {
  const parts = sel.trim().split(/\s+/);
  let seeds = [root];
  for (const part of parts) {
    const next = [];
    for (const seed of seeds) {
      walk(seed, (el) => {
        if (match(el, part)) next.push(el);
      });
    }
    seeds = next;
  }
  return seeds;
}

class ClassList {
  constructor(el) {
    this.el = el;
  }
  add(c) {
    this.el._classes.add(c);
  }
  remove(...names) {
    for (const c of names) this.el._classes.delete(c);
  }
  toggle(c, force) {
    const has = this.el._classes.has(c);
    const next = force === undefined ? !has : !!force;
    if (next) this.el._classes.add(c);
    else this.el._classes.delete(c);
    return next;
  }
  contains(c) {
    return this.el._classes.has(c);
  }
}

function parseAttrs(el, raw) {
  const re = /([:@\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+)))?/g;
  let m;
  while ((m = re.exec(raw))) {
    const name = m[1];
    const val = m[2] ?? m[3] ?? m[4] ?? "";
    if (name === "class") {
      val.split(/\s+/).filter(Boolean).forEach((c) => el._classes.add(c));
    } else if (name === "id") {
      el.id = val;
      el.attrs.id = val;
    } else if (name === "hidden") {
      el.hidden = true;
    } else {
      el.attrs[name] = val;
    }
  }
}

class El {
  constructor(tag) {
    this.tagName = String(tag || "div").toUpperCase();
    this.children = [];
    this.parent = null;
    this.attrs = {};
    this._classes = new Set();
    this._listeners = {};
    this.hidden = false;
    this.value = "";
    this.disabled = false;
    this._text = null;
    this.id = "";
    this.classList = new ClassList(this);
    this.style = {};
    const self = this;
    this.dataset = new Proxy(
      {},
      {
        get(_t, key) {
          if (typeof key !== "string") return undefined;
          const name = "data-" + key.replace(/[A-Z]/g, (ch) => "-" + ch.toLowerCase());
          return self.attrs[name];
        },
        set(_t, key, value) {
          const name = "data-" + String(key).replace(/[A-Z]/g, (ch) => "-" + ch.toLowerCase());
          self.attrs[name] = String(value);
          return true;
        },
      }
    );
  }
  get textContent() {
    if (this.tagName === "#TEXT") return this._text || "";
    if (this._text != null && this.children.length === 0) return this._text;
    return this.children.map((c) => c.textContent).join("");
  }
  set textContent(v) {
    this._text = String(v);
    this.children = [];
  }
  getAttribute(name) {
    if (name === "id") return this.id || null;
    if (name === "class") return [...this._classes].join(" ");
    if (Object.prototype.hasOwnProperty.call(this.attrs, name)) return this.attrs[name];
    return null;
  }
  setAttribute(name, value) {
    const v = String(value);
    this.attrs[name] = v;
    if (name === "id") this.id = v;
    if (name === "class") {
      this._classes = new Set(v.split(/\s+/).filter(Boolean));
    }
  }
  addEventListener(type, fn) {
    (this._listeners[type] || (this._listeners[type] = [])).push(fn);
  }
  remove() {
    if (!this.parent) return;
    this.parent.children = this.parent.children.filter((c) => c !== this);
  }
  querySelector(sel) {
    return queryAll(this, sel)[0] || null;
  }
  querySelectorAll(sel) {
    return queryAll(this, sel);
  }
  closest(sel) {
    let n = this;
    while (n && n.tagName) {
      if (match(n, sel)) return n;
      n = n.parent;
    }
    return null;
  }
  set innerHTML(html) {
    const kids = parseHtml(html);
    this.children = kids;
    this._text = null;
    for (const kid of kids) kid.parent = this;
  }
  insertAdjacentHTML(pos, html) {
    const kids = parseHtml(html);
    for (const kid of kids) kid.parent = this;
    if (pos === "beforeend") this.children.push(...kids);
  }
  focus() {}
  select() {}
  setSelectionRange() {}
  click() {
    for (const fn of this._listeners.click || []) fn({ target: this });
  }
}

function parseHtml(html) {
  const root = new El("div");
  const stack = [root];
  const re = /<!--[\s\S]*?-->|<(\/?)([a-zA-Z][\w-]*)([^>]*?)(\/?)>|([^<]+)/g;
  let m;
  while ((m = re.exec(html))) {
    if (m[5] != null) {
      const text = m[5].replace(/\s+/g, " ").trim();
      if (!text) continue;
      const node = new El("#text");
      node.tagName = "#TEXT";
      node._text = text;
      node.parent = stack[stack.length - 1];
      stack[stack.length - 1].children.push(node);
      continue;
    }
    const closing = m[1] === "/";
    const tag = m[2].toLowerCase();
    if (closing) {
      for (let i = stack.length - 1; i > 0; i--) {
        if (stack[i].tagName === tag.toUpperCase()) {
          stack.length = i;
          break;
        }
      }
      continue;
    }
    const el = new El(tag);
    parseAttrs(el, m[3] || "");
    el.parent = stack[stack.length - 1];
    stack[stack.length - 1].children.push(el);
    const selfClose = m[4] === "/" || tag === "br" || tag === "img" || tag === "input";
    if (!selfClose) stack.push(el);
  }
  return root.children;
}

function pageHtml(attrs) {
  return `<body ${attrs}>
    <button type="button" id="ai-fab" aria-expanded="false"><span class="ai-badge" hidden></span></button>
    <button type="button" id="ai-entry" aria-expanded="false">AI</button>
    <div id="ai-sheet" class="ai-sheet" hidden>
      <header class="ai-head">
        <div id="ai-title">Title</div>
        <button type="button" id="ai-max" aria-pressed="false">Expand</button>
        <button type="button" id="ai-close">Close</button>
      </header>
      <div id="operator-chat-root" class="operator-chat-root" data-chat-scope="home"></div>
    </div>
  </body>`;
}

function boot(opts) {
  const store = new Map(Object.entries(opts.storage || {}));
  const calls = [];
  const navigated = [];
  const bodyKids = parseHtml(pageHtml(opts.body || 'data-page="home"'));
  const body = new El("body");
  body.children = bodyKids;
  for (const kid of bodyKids) kid.parent = body;
  body.getAttribute = function (name) {
    const m = String(opts.body || 'data-page="home"').match(new RegExp(name + '="([^"]*)"'));
    return m ? m[1] : null;
  };
  const document = {
    readyState: "complete",
    body,
    getElementById(id) {
      if (body.id === id) return body;
      return queryAll(body, "#" + id)[0] || null;
    },
    querySelector(sel) {
      return queryAll(body, sel)[0] || null;
    },
    querySelectorAll(sel) {
      return queryAll(body, sel);
    },
    addEventListener() {},
  };
  const hrefBox = { href: opts.href || "http://127.0.0.1:8792/" };
  const location = {};
  Object.defineProperty(location, "href", {
    get() {
      return hrefBox.href;
    },
    set(v) {
      navigated.push(v);
      throw new Error("navigated " + v);
    },
  });
  const sandbox = {
    document,
    sessionStorage: {
      getItem(k) {
        return store.has(k) ? store.get(k) : null;
      },
      setItem(k, v) {
        store.set(String(k), String(v));
      },
      removeItem(k) {
        store.delete(k);
      },
    },
    setTimeout,
    clearTimeout,
    console,
    location,
    TextDecoder: class {
      decode(value) {
        if (value == null) return "";
        if (typeof value === "string") return value;
        return Buffer.from(value).toString("utf8");
      }
    },
    __calls: calls,
    __payload: opts.payload || {
      id: "abc",
      messages: [{ role: "user", content: "persisted hi" }],
    },
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.runInNewContext(
    `globalThis.fetch = function (url) {
      __calls.push(String(url));
      var payload = __payload;
      return Promise.resolve({
        ok: payload.ok !== false,
        status: payload.ok === false ? 404 : 200,
        json: function () { return Promise.resolve(payload); },
      });
    };`,
    sandbox
  );
  vm.runInNewContext(CHAT, sandbox, { filename: "chat.js" });
  return { sandbox, document, calls, navigated, store };
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe("bubble sheet maximize", () => {
  it("expands in place and keeps the same session, draft, and root", async () => {
    const { sandbox, document, calls, navigated } = boot({
      storage: { "vf-chat:fleet": "abc" },
    });
    const chat = sandbox.VulnForgeChat;
    const root = document.getElementById("operator-chat-root");
    chat.openSheet();
    await wait(30);
    const input = document.getElementById("oc-input");
    const box = document.getElementById("oc-messages");
    assert.equal(chat.isSheetOpen(), true);
    assert.equal(document.getElementById("ai-sheet").hidden, false);
    assert.match(box.textContent, /persisted hi/);
    assert.equal(calls.length, 2);
    assert.match(calls[0], /\/api\/chat\/sessions\/abc$/);
    assert.match(calls[1], /\/api\/chat\/sessions$/);
    input.value = "keep this draft";
    const beforeRoot = root.innerHTML ? root : root;
    assert.equal(root.dataset.ready, "1");

    document.getElementById("ai-max").click();
    assert.equal(chat.isMaximized(), true);
    assert.equal(document.getElementById("ai-sheet").classList.contains("is-max"), true);
    assert.equal(document.getElementById("ai-max").textContent, "Minimize");
    assert.equal(input.value, "keep this draft");
    assert.equal(document.getElementById("oc-input"), input);
    assert.match(document.getElementById("oc-messages").textContent, /persisted hi/);
    assert.equal(document.getElementById("operator-chat-root"), root);
    assert.equal(root.dataset.ready, "1");
    assert.equal(calls.length, 2);
    assert.deepEqual(navigated, []);
    assert.equal(beforeRoot, root);

    chat.toggleMaximize();
    assert.equal(chat.isMaximized(), false);
    assert.equal(document.getElementById("ai-max").textContent, "Expand");
    assert.equal(input.value, "keep this draft");
    assert.match(document.getElementById("oc-messages").textContent, /persisted hi/);
    assert.equal(calls.length, 2);
    assert.deepEqual(navigated, []);
  });

  it("restores a run-scoped session into the same root", async () => {
    const { sandbox, document, calls } = boot({
      body: 'data-page="run" data-run-key="toy/run-001"',
      storage: { "vf-chat:toy/run-001": "runsess" },
      payload: { id: "runsess", messages: [{ role: "assistant", content: "run status" }] },
    });
    sandbox.VulnForgeChat.openSheet();
    await wait(30);
    assert.match(calls[0], /\/api\/runs\/toy\/run-001\/chat\/sessions\/runsess$/);
    assert.match(calls[1], /\/api\/runs\/toy\/run-001\/chat\/sessions$/);
    assert.match(document.getElementById("oc-messages").textContent, /run status/);
    const root = document.getElementById("operator-chat-root");
    sandbox.VulnForgeChat.toggleMaximize();
    sandbox.VulnForgeChat.toggleMaximize();
    assert.equal(document.getElementById("operator-chat-root"), root);
    assert.match(document.getElementById("oc-messages").textContent, /run status/);
  });
});

function jsonResponse(data, status) {
  return {
    ok: status ? status < 400 : true,
    status: status || 200,
    headers: { get: () => "application/json" },
    json: () => Promise.resolve(data),
  };
}

function ndjsonResponse(lines, hold) {
  let i = 0;
  const encoded = lines.map((line) => Buffer.from(JSON.stringify(line) + "\n"));
  return {
    ok: true,
    status: 200,
    headers: { get: (h) => (String(h).toLowerCase() === "content-type" ? "application/x-ndjson" : "") },
    body: {
      getReader() {
        return {
          async read() {
            if (hold && i === hold.at) await hold.gate;
            if (i >= encoded.length) return { done: true, value: undefined };
            return { done: false, value: encoded[i++] };
          },
        };
      },
    },
    json: () => Promise.resolve({}),
  };
}

describe("history sidebar, parallel panes, live stream", () => {
  it("lists previous chats and restores one without dropping the open pane", async () => {
    const { sandbox, document } = boot({
      storage: { "vf-chat:fleet": "abc" },
    });
    const payloads = {
      "/api/chat/sessions": {
        sessions: [
          { id: "abc", preview: "persisted hi" },
          { id: "older", preview: "older topic" },
        ],
      },
      "/api/chat/sessions/abc": {
        id: "abc",
        messages: [{ role: "user", content: "persisted hi" }],
      },
      "/api/chat/sessions/older": {
        id: "older",
        messages: [{ role: "assistant", content: "older body" }],
      },
    };
    sandbox.fetch = (url) => {
      const data = payloads[String(url)] || { sessions: [] };
      return Promise.resolve(jsonResponse(data, data.missing ? 404 : 200));
    };
    sandbox.VulnForgeChat.openSheet();
    await wait(40);
    const listed = document.querySelectorAll(".oc-session");
    const older = listed.find((btn) => btn.getAttribute("data-session-id") === "older");
    assert.ok(older, "older session is in the sidebar");
    assert.equal(document.getElementById("oc-new").textContent, "New chat");
    older.click();
    await wait(40);
    const panes = document.querySelectorAll(".oc-pane");
    assert.equal(panes.length, 2);
    assert.match(panes[0].textContent, /persisted hi/);
    assert.match(document.querySelector(".oc-pane.is-active").textContent, /older body/);
  });

  it("streams tool calls before done, keeps the busy pane, and toasts when unfocused", async () => {
    const { sandbox, document } = boot({});
    let release;
    const hold = { at: 2, gate: new Promise((resolve) => { release = resolve; }) };
    const lines = [
      { event: "session", session_id: "live1" },
      { event: "message", message: { role: "assistant", content: "looking at the fleet" } },
      { event: "message", message: { role: "tool", name: "list_runs", content: { ok: true, count: 1 } } },
      { event: "message", message: { role: "assistant", content: "final answer here" } },
      { event: "done", ok: true, session_id: "live1", pending_confirm: null, ui_hints: {} },
    ];
    const seen = [];
    sandbox.fetch = (url, opts) => {
      const u = String(url);
      seen.push({ url: u, accept: opts && opts.headers && opts.headers.Accept });
      if (opts && opts.method === "POST") return Promise.resolve(ndjsonResponse(lines, hold));
      if (u.endsWith("/sessions")) return Promise.resolve(jsonResponse({ sessions: [] }));
      return Promise.resolve(jsonResponse({ id: "live1", messages: [] }));
    };
    sandbox.VulnForgeChat.openSheet();
    await wait(20);
    const input = document.getElementById("oc-input");
    input.value = "list runs please";
    document.getElementById("oc-send").click();
    await wait(30);
    const first = document.querySelectorAll(".oc-pane")[0];
    assert.match(first.textContent, /looking at the fleet/);
    assert.doesNotMatch(first.textContent, /final answer here/);
    assert.equal(document.querySelectorAll(".oc-session.is-busy").length, 1);
    assert.equal(document.querySelector(".oc-tab.is-busy").getAttribute("aria-busy"), "true");
    assert.equal(seen.find((row) => row.accept).accept, "application/x-ndjson");

    document.getElementById("oc-new").click();
    assert.equal(document.querySelectorAll(".oc-pane").length, 2);
    assert.match(document.querySelectorAll(".oc-pane")[0].textContent, /looking at the fleet/);
    assert.doesNotMatch(document.querySelector(".oc-pane.is-active").textContent, /looking at the fleet/);
    assert.equal(document.querySelectorAll(".oc-session.is-busy").length, 1);

    release();
    await wait(40);
    const panes = document.querySelectorAll(".oc-pane");
    assert.match(panes[0].textContent, /tool: list_runs/);
    assert.match(panes[0].textContent, /final answer here/);
    assert.doesNotMatch(document.querySelector(".oc-pane.is-active").textContent, /final answer here/);
    assert.equal(document.querySelectorAll(".oc-session.is-busy").length, 0);
    assert.match(document.querySelector(".oc-toast").textContent, /Done/);
  });
});
