// Minimal UI entry (fixture) — no real XSS sink required for plan tests.
export function mount(root) {
  root.innerHTML = "<div id=app>mono_synth ui</div>";
}
