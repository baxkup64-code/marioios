let ok = 0, bad = 0;
const T = (name, c) => { if (c) ok++; else { bad++; console.log("FAIL:", name); } };
// --- Pointer
const p = ptr("0x1000");
T("add", p.add(0x10).toString() === "0x1010");
T("sub/and", p.sub(1).toString() === "0xfff" && ptr(0x1234).and(ptr(0xff)).toString() === "0x34");
T("isNull/equals/compare", ptr(0).isNull() && p.equals(ptr(4096)) && p.compare(ptr(1)) === 1 && NULL.isNull());
T("shr", ptr(0x100).shr(4).toString() === "0x10");
T("toInt32", ptr(-1).toInt32() === -1 && ptr(0x80000000).toUInt32() === 0x80000000);
T("instanceof", p instanceof NativePointer);
// --- Memory
const m = Memory.alloc(64);
m.writeS32(-5); T("S32", m.readS32() === -5 && m.readU32() === 0xfffffffb);
m.add(8).writePointer(ptr("0xdeadbeef")); T("ptr", m.add(8).readPointer().toString() === "0xdeadbeef");
m.add(16).writeU8(200); m.add(17).writeU16(65000); T("u8/u16", m.add(16).readU8() === 200 && m.add(17).readU16() === 65000);
m.add(24).writeFloat(1.5); T("float", m.add(24).readFloat() === 1.5);
m.add(32).writeDouble(2.25); T("double", m.add(32).readDouble() === 2.25);
m.add(40).writeU64(ptr("0x123456789")); T("u64", m.add(40).readU64() === 0x123456789);
const s = Memory.allocUtf8String("hallo"); T("utf8", s.readUtf8String() === "hallo" && s.readUtf8String(3) === "hal");
const bytes = new Uint8Array([1, 2, 3, 4]); m.add(48).writeByteArray(bytes.buffer);
T("bytes", new DataView(m.add(48).readByteArray(4)).getUint32(0, true) === 0x04030201);
let thrown = false; try { ptr(8).readU32(); } catch (e) { thrown = true; } T("access violation -> Exception", thrown);
thrown = false; try { ptr(8).writePointer(ptr(1)); } catch (e) { thrown = true; } T("write violation", thrown);
T("range valid", Process.findRangeByAddress(m) !== null && Process.findRangeByAddress(ptr(16)) === null);
Memory.copy(m.add(56), s, 6); T("copy", m.add(56).readUtf8String() === "hallo");
// --- NativeFunction
const f = (n, r, a) => new NativeFunction(Module.findExportByName(null, n), r, a);
T("strlen", f("strlen", "ulong", ["pointer"])(s) === 5);
T("abs", f("abs", "int", ["int"])(-7) === 7);
T("sqrt double", f("sqrt", "double", ["double"])(81) === 9);
T("powf float", f("powf", "float", ["float", "float"])(2, 10) === 1024);
T("atan2 2 doubles", Math.abs(f("atan2", "double", ["double", "double"])(1, 1) - Math.PI / 4) < 1e-9);
T("memset ptr ret", f("memset", "pointer", ["pointer", "int", "ulong"])(m, 0x41, 4).equals(m) && m.readU32() === 0x41414141);
T("toupper+bool", f("isalpha", "int", ["int"])(65) !== 0);
let nf0 = false; try { new NativeFunction(NULL, "void", []); } catch (e) { nf0 = true; } T("NativeFunction(NULL) wirft", nf0);
// --- NativeCallback (qsort-Komparator)
const arr = Memory.alloc(5 * 4); [5, 3, 9, 1, 7].forEach((v, i) => arr.add(i * 4).writeS32(v));
const cmp = new NativeCallback((a, b) => a.readS32() - b.readS32(), "int", ["pointer", "pointer"]);
f("qsort", "void", ["pointer", "ulong", "ulong", "pointer"])(arr, 5, 4, cmp);
T("qsort+callback", [0, 1, 2, 3, 4].map((i) => arr.add(i * 4).readS32()).join() === "1,3,5,7,9");
// float-Callback: bsearch-artig ueber double-Argument nicht noetig; Callback mit void-Rueckgabe + Argumente
let got = null; const cb2 = new NativeCallback((x, y) => { got = [x.toString(), y]; }, "void", ["pointer", "int"]);
new NativeFunction(cb2, "void", ["pointer", "int"])(ptr(0x77), 42); T("callback roundtrip", got && got[0] === "0x77" && got[1] === 42);
// --- Interceptor
const base = Process.mainModule.base;
const log = [];
const lst = Interceptor.attach(base.add(0x100), {
  onEnter(args) { this.a0 = args[0]; log.push("enter " + args[0] + " " + args[1]); args[1] = ptr(99); },
  onLeave(rv) { log.push("leave " + this.a0 + " rv=" + rv); rv.replace(ptr(1234)); },
});
Interceptor.attach(base.add(0x100), { onEnter() { log.push("second"); } });
Interceptor.attach(base.add(0x999), { onEnter() {} });   // nicht vorgepatcht -> geloggt, kein Fehler
const regs = Memory.alloc(160); regs.writeU64(ptr(0xaa)); regs.add(8).writeU64(ptr(0xbb));
T("enter need-leave", __km_enter(0, Number(regs.toString(10)), 1) === true);
T("arg write-back", regs.add(8).readU64() === 99);
regs.writeU64(ptr(0x5555)); __km_leave(0, Number(regs.toString(10)), 1);
T("leave sees this + replaces retval", regs.readU64() === 1234 && log.join("|") === "enter 0xaa 0xbb|second|leave 0xaa rv=0x5555");
lst.detach(); T("detach", __km_enter(0, Number(regs.toString(10)), 2) === false);
// --- Timer
const order = []; setTimeout(() => order.push("b"), 80); setTimeout(() => order.push("a"), 20);
let n = 0; const iv = setInterval(() => { n++; if (n === 3) { clearInterval(iv); order.push("iv"); } }, 30);
setTimeout(() => { T("timer order", order.join() === "a,iv,b" || order.join() === "a,b,iv"); T("interval stopped", n === 3);
  console.log("ERGEBNIS: " + ok + " ok, " + bad + " fehlgeschlagen"); }, 400);
// --- BigInt & Co (vom Skript genutzt)
T("BigInt pow", (3n ** 4n) === 81n && BigInt.asUintN(64, -1n) === 0xffffffffffffffffn);
// --- Struktur (CGRect-Stil) als HFA: hypot-artig ueber fma(double,double,double) + HFA-Reihenfolge pruefen
const rect = Memory.alloc(32);
const sumrect = new NativeFunction(Module.findExportByName(null, "fmax"), "double", ["double", "double"]);
T("fmax", sumrect(3, 9) === 9);
let hfaErr = null; try { new NativeFunction(Module.findExportByName(null, "strlen"), "void", [["double", "double", "double", "double"]]); } catch (e) { hfaErr = e; }
T("HFA-Typ wird akzeptiert", hfaErr === null);
