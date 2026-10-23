// prelude.js -- baut aus den C-Natives (__n) die Frida-API, die debug_ios.ts erwartet.
(function (G) {
  "use strict";
  const N = G.__n;
  const fmt = (a) => {
    if (typeof a === "string") return a;
    if (a instanceof Error) return a.stack || String(a);
    if (a === null || a === undefined || typeof a !== "object") return String(a);
    if (a instanceof NativePointer) return a.toString();
    try { return JSON.stringify(a); } catch (_) { return String(a); }
  };
  const logf = (...a) => N.log(a.map(fmt).join(" "));
  G.console = { log: logf, info: logf, warn: logf, error: logf, debug: logf };

  G.NULL = ptr(0);
  G.Memory = {
    alloc: (n) => N.alloc(n),
    allocUtf8String: (s) => N.allocUtf8(String(s)),
    copy: (d, s, n) => N.copy(d, s, n),
    protect: () => true,
  };
  G.NativeFunction = function NativeFunction(addr, ret, args) { return N.nfn(addr, ret, args); };
  G.NativeCallback = function NativeCallback(fn, ret, args) { return N.ncb(fn, ret, args); };

  const base = N.base();
  G.Process = {
    arch: "arm64", platform: "darwin", pointerSize: 8,
    mainModule: { name: "main", base: base, path: "" },
    findRangeByAddress: (p) => N.range(p),
    enumerateRanges: () => [],
  };
  G.Module = {
    findExportByName: (mod, name) => N.dlsym(name),
    getGlobalExportByName: (name) => { const p = N.dlsym(name); if (p === null) throw new Error("unable to find global export: " + name); return p; },
  };
  // Frida-File: new File(path, "w"|"a") + write/flush/close (ohne dieses ging Speichern ohne JIT nie: "File is not a constructor")
  class File {
    constructor(path, mode) {
      this._p = String(path); this._m = String(mode || "r"); this._buf = []; this._open = false; this._closed = false;
      if (this._m[0] !== "w" && this._m[0] !== "a") throw new Error("File: nur Modus w/a unterstuetzt, Lesen ueber File.readAllText");
    }
    write(data) {
      if (this._closed) throw new Error("File ist geschlossen");
      this._buf.push(typeof data === "string" ? data : String.fromCharCode.apply(null, Array.from(new Uint8Array(data))));
      return this;
    }
    flush() {
      if (this._closed) return;
      const txt = this._buf.join(""); this._buf = [];
      if (this._m[0] === "w" && !this._open) N.writeFile(this._p, txt, false);   // erstes Schreiben: Datei neu anlegen/ersetzen
      else if (txt.length) N.writeFile(this._p, txt, true);
      this._open = true;
    }
    close() { if (this._closed) return; this.flush(); this._closed = true; }
    static readAllText(p) { return N.readFile(String(p)); }
    static writeAllText(p, t) { N.writeFile(String(p), String(t), false); }
  }
  G.File = File;
  G.Frida = { version: "kitmod-qjs", heapSize: 0 };
  G.Script = { runtime: "QJS" };

  // ---------------- Timer
  let tid = 0; const timers = new Map();
  const mk = (rep) => (fn, ms, ...args) => { const id = ++tid; timers.set(id, { fn, args, rep }); N.tmSet(id, +ms || 0, rep ? 1 : 0); return id; };
  G.setTimeout = mk(false); G.setInterval = mk(true);
  G.clearTimeout = G.clearInterval = (id) => { timers.delete(id); N.tmClear(id | 0); };
  G.setImmediate = (fn, ...a) => G.setTimeout(fn, 0, ...a);
  G.__km_timer = (id) => {
    const t = timers.get(id); if (!t) return;
    if (!t.rep) timers.delete(id);
    try { t.fn(...t.args); } catch (e) { logf("Timer-Fehler:", e); }
  };

  // ---------------- Interceptor (nur auf vorgepatchte Stellen, siehe hooks.json)
  class Args {}
  for (let i = 0; i < 8; i++) Object.defineProperty(Args.prototype, i, { get() { return N.regGet(this.r, i); }, set(v) { N.regSet(this.r, i, v); } });
  const L = new Map();       // idx -> [listener]
  const ctxs = new Map();    // token -> [listeners, ctx[]]
  G.Interceptor = {
    attach(target, cb) {
      const idx = N.hookIndex(target);
      const l = typeof cb === "function" ? { onEnter: cb } : cb;
      if (idx < 0) { logf("[kitmod] Hook nicht vorgepatcht (RVA 0x" + target.sub(base).toString() .replace("0x", "") + ") - ignoriert"); return { detach() {} }; }
      if (!L.has(idx)) L.set(idx, []);
      L.get(idx).push(l);
      return { detach() { const a = L.get(idx), i = a.indexOf(l); if (i >= 0) a.splice(i, 1); } };
    },
    detachAll() { L.clear(); },
    flush() {},
  };
  G.__km_enter = (idx, r, token) => {
    const ls = L.get(idx); if (!ls || ls.length === 0) return false;
    const snap = ls.slice(), args = new Args(); args.r = r;
    const cx = []; let need = false;
    for (const l of snap) {
      const ctx = {}; cx.push(ctx);
      if (l.onEnter) { try { l.onEnter.call(ctx, args); } catch (e) { logf("onEnter-Fehler:", e); } }
      if (l.onLeave) need = true;
    }
    if (need) ctxs.set(token, [snap, cx]);
    return need;
  };
  G.__km_leave = (idx, r, token) => {
    const e = ctxs.get(token); if (!e) return; ctxs.delete(token);
    const rv = N.regGet(r, 0); rv.replace = (v) => N.regSet(r, 0, v);
    e[0].forEach((l, i) => { if (l.onLeave) { try { l.onLeave.call(e[1][i], rv); } catch (er) { logf("onLeave-Fehler:", er); } } });
  };
})(globalThis);
