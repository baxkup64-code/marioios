#!/usr/bin/env python3
"""
Statisches Hooking ohne JIT.

Auf iOS ohne JIT darf zur Laufzeit kein Code veraendert werden. Deshalb wird die Binary EINMAL VOR dem Signieren
(Sideloadly/AltStore signieren danach neu) veraendert:
  * Am Anfang jeder Hook-Funktion wird 1 Instruktion (4 Byte) durch  `b cave`  ersetzt.
  * Die Caves liegen in einem neuen Segment __KMTEXT (r-x):  adrp x16,slot ; ldr x16,[x16,#off] ; br x16
  * Die Slots liegen in einem neuen Segment __KMDATA (rw-). Die Dylib traegt zur Laufzeit ihre Trampolin-Adressen dort
    ein (reine Daten-Schreibzugriffe, kein JIT noetig).
  * Das Trampolin in der Dylib sichert die Argument-Register, ruft den C-Handler (onEnter), fuehrt die verdraengte
    Original-Instruktion aus und springt auf Funktion+4 zurueck.
  * onLeave: LR wird auf ein Leave-Trampolin umgebogen (Schattenstack, ein Thread-Kontext angenommen).

Aufruf:  python3 build_hooks.py <entschluesselte_Binary> <hooks.json> <out_Binary> <dylib_dir>
Erzeugt: <out_Binary> (gepatcht), <dylib_dir>/kitmod_gen.h, <dylib_dir>/kitmod_tramp.S

STATUS: NICHT gegen eine echte Binary getestet (mir lag nur das Skript vor). Bricht bei Unklarem mit Fehlermeldung ab.
Benoetigt:  pip install lief capstone
"""
import json
import struct
import sys

import capstone
import lief

PAGE = 0x4000   # arm64-iOS Seitengroesse
CAVE = 16       # Bytes je Cave
PC_REL = {"adr", "ldr", "ldrsw", "prfm", "b", "bl", "cbz", "cbnz", "tbz", "tbnz"}


def die(msg):
    sys.exit("FEHLER: " + msg)


def enc_b(src, dst):
    d = (dst - src) // 4
    if not -(1 << 25) <= d < (1 << 25):
        die(f"Sprung zu weit (0x{src:x} -> 0x{dst:x}); Cave-Segment liegt >128MB entfernt")
    return 0x14000000 | (d & 0x3ffffff)


def enc_adrp(rd, src_va, dst_va):
    imm = ((dst_va & ~0xfff) - (src_va & ~0xfff)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7ffff) << 5) | rd


def enc_ldr_x(rt, rn, off):
    return 0xF9400000 | ((off // 8) << 10) | (rn << 5) | rt


BR_X16 = 0xD61F0200
NOP = 0xD503201F


def displaced_asm(insn, rva):
    """Assembler-Zeilen, die die verdraengte Instruktion an anderer Stelle gleichwertig ausfuehren."""
    word = struct.unpack("<I", bytes(insn.bytes))[0]
    mn, ops = insn.mnemonic, insn.op_str
    if any(r in ops for r in ("x16", "x17", "w16", "w17")):
        die(f"RVA 0x{rva:x}: erste Instruktion '{mn} {ops}' nutzt x16/x17")
    if mn == "adrp":
        rd = word & 0x1f
        page = int(ops.split("#")[1], 16) - 0x100000000   # absolute Zielseite als RVA
        return [f"    KM_LOAD_BASE_PLUS {rd}, 0x{page:x}"]
    if mn in PC_REL or mn.startswith("b."):
        die(f"RVA 0x{rva:x}: erste Instruktion '{mn} {ops}' ist PC-relativ und noch nicht unterstuetzt "
            f"-> Zeile melden oder Hook-Punkt weiter hinten waehlen")
    return [f"    .inst 0x{word:08x}   // {mn} {ops}"]


def main():
    if len(sys.argv) != 5:
        die(__doc__)
    src, hjson, out, dylib_dir = sys.argv[1:]
    hooks = [h for h in json.load(open(hjson))["hooks"]]
    fat = lief.MachO.parse(src)
    if fat is None:
        die("Binary nicht lesbar")
    b = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    if b is None:
        die("keine arm64-Slice")
    image_base = b.get_segment("__TEXT").virtual_address
    if image_base != 0x100000000:
        print(f"Hinweis: Image-Base ist 0x{image_base:x} (das Skript nimmt 0x100000000 an)")
    n = len(hooks)
    cave_size = max(PAGE, -(-n * CAVE // PAGE) * PAGE)
    data_size = max(PAGE, -(-n * 8 // PAGE) * PAGE)

    # Pass 1: Segmente mit Platzhalter anlegen, damit LIEF die Adressen vergibt
    seg_t = lief.MachO.SegmentCommand("__KMTEXT", [0] * cave_size)
    seg_t.init_protection = 5
    seg_t.max_protection = 5      # r-x
    seg_d = lief.MachO.SegmentCommand("__KMDATA", [0] * data_size)
    seg_d.init_protection = 3
    seg_d.max_protection = 3      # rw-
    seg_t = b.add(seg_t)
    seg_d = b.add(seg_d)
    cave_va, slot_va = seg_t.virtual_address, seg_d.virtual_address
    print(f"__KMTEXT @ 0x{cave_va:x}, __KMDATA @ 0x{slot_va:x}")

    # Pass 2: Caves schreiben und Hook-Stellen patchen
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    cave_bytes = bytearray(cave_size)
    asm = []
    for i, h in enumerate(hooks):
        rva = int(h["rva"], 16)
        va = image_base + rva
        orig = bytes(b.get_content_from_virtual_address(va, 4))
        insn = next(md.disasm(orig, va), None)
        if insn is None:
            die(f"{h['name']}: RVA 0x{rva:x} nicht dekodierbar")
        asm.append((i, h, displaced_asm(insn, rva)))
        c_va, s_va = cave_va + i * CAVE, slot_va + i * 8
        cave_bytes[i * CAVE:(i + 1) * CAVE] = struct.pack(
            "<4I", enc_adrp(16, c_va, s_va), enc_ldr_x(16, 16, s_va & 0xfff), BR_X16, NOP)
        b.patch_address(va, list(struct.pack("<I", enc_b(va, c_va))))
        print(f"  {h['name']:<16} RVA 0x{rva:08x}  orig: {insn.mnemonic} {insn.op_str}")
    seg_t.content = list(cave_bytes)

    if b.has_code_signature:
        b.remove_signature()
    b.write(out)
    print("geschrieben:", out)

    with open(f"{dylib_dir}/kitmod_gen.h", "w") as f:
        f.write("// AUTO-GENERIERT von build_hooks.py\n#pragma once\n")
        f.write(f"#define KM_NHOOKS {n}\n#define KM_SLOT_RVA 0x{slot_va - image_base:x}ULL\n")
        f.write("enum { " + ", ".join(f"KM_{h['name']}" for _, h, _ in asm) + " };\n")
        f.write("static const uint32_t KM_RVAS[KM_NHOOKS] = {"
                + ", ".join(h["rva"] for _, h, _ in asm) + "};\n")
        for i, _, _ in asm:
            f.write(f"extern void km_tramp_{i}(void); extern void km_leave_{i}(void);\n")
        f.write("static void *const KM_TRAMPS[KM_NHOOKS] = {"
                + ", ".join(f"km_tramp_{i}" for i, _, _ in asm) + "};\n")
        f.write("static void *const KM_LEAVES[KM_NHOOKS] = {"
                + ", ".join(f"km_leave_{i}" for i, _, _ in asm) + "};\n")
    with open(f"{dylib_dir}/kitmod_tramp.S", "w") as f:
        f.write(TRAMP_HEAD)
        for i, h, body in asm:
            rva = int(h["rva"], 16)
            f.write(f"\n// ---- {h['name']} (RVA 0x{rva:x}) ----\n")
            f.write(f".globl _km_tramp_{i}\n.p2align 2\n_km_tramp_{i}:\n"
                    f"    KM_SAVE\n    mov x0, #{i}\n    mov x1, sp\n    bl _kitmod_enter\n"
                    f"    mov x16, x0\n    KM_RESTORE\n    mov x30, x16\n")
            f.write("\n".join(body) + "\n")
            f.write(f"    KM_JUMP_BASE_PLUS 0x{rva + 4:x}\n")
            f.write(f".globl _km_leave_{i}\n.p2align 2\n_km_leave_{i}:\n"
                    f"    KM_SAVE\n    mov x0, #{i}\n    mov x1, sp\n    bl _kitmod_leave\n"
                    f"    mov x16, x0\n    KM_RESTORE\n    br x16\n")
    print("kitmod_gen.h / kitmod_tramp.S erzeugt")


# Frame-Layout (0xA0 Byte) muss zu km_regs in kitmod.c passen
TRAMP_HEAD = r""".text
.macro KM_SAVE
    sub sp, sp, #0xA0
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    str x8, [sp, #64]
    stp x29, x30, [sp, #72]
    stp d0, d1, [sp, #88]
    stp d2, d3, [sp, #104]
    stp d4, d5, [sp, #120]
    stp d6, d7, [sp, #136]
.endmacro
.macro KM_RESTORE
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldr x8, [sp, #64]
    ldp x29, x30, [sp, #72]
    ldp d0, d1, [sp, #88]
    ldp d2, d3, [sp, #104]
    ldp d4, d5, [sp, #120]
    ldp d6, d7, [sp, #136]
    add sp, sp, #0xA0
.endmacro
// Register x\r = Binary-Base + \off
.macro KM_LOAD_BASE_PLUS r, off
    adrp x17, _kitmod_base@PAGE
    ldr  x17, [x17, _kitmod_base@PAGEOFF]
    movz x16, #(\off & 0xffff)
    movk x16, #((\off >> 16) & 0xffff), lsl #16
    add  x\r, x17, x16
.endmacro
.macro KM_JUMP_BASE_PLUS off
    adrp x17, _kitmod_base@PAGE
    ldr  x17, [x17, _kitmod_base@PAGEOFF]
    movz x16, #(\off & 0xffff)
    movk x16, #((\off >> 16) & 0xffff), lsl #16
    add  x16, x17, x16
    br   x16
.endmacro
"""

if __name__ == "__main__":
    main()
