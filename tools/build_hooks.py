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

Verdraengte Instruktionen, die relativ zum PC arbeiten (b, bl, b.cond, cbz, cbnz, tbz, tbnz, adr, adrp,
ldr literal), werden hier dekodiert und im Trampolin mit absoluten Adressen (Binary-Base + RVA) neu aufgebaut.

Aufruf:  python3 build_hooks.py <entschluesselte_Binary> <hooks.json> <out_Binary> <dylib_dir>
Erzeugt: <out_Binary> (gepatcht), <dylib_dir>/kitmod_gen.h, <dylib_dir>/kitmod_tramp.S

STATUS: NICHT gegen eine echte Binary getestet (mir lag nur das Skript vor). Bricht bei Unklarem mit Fehlermeldung ab.
Benoetigt:  pip install lief capstone
"""
import json
import re
import struct
import sys

import capstone
import lief

PAGE = 0x4000   # arm64-iOS Seitengroesse
CAVE = 16       # Bytes je Cave
CONDS = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "al"]
REG1617 = re.compile(r"\b[xw](16|17)\b")


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


def sx(value, bits):
    """Vorzeichenerweiterung."""
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def gpr(n, wide):
    if n == 31:
        return "xzr" if wide else "wzr"
    return f"{'x' if wide else 'w'}{n}"


def displaced_asm(insn, rva, idx, image_base):
    """
    Assembler-Zeilen, die die verdraengte Instruktion an anderer Stelle gleichwertig ausfuehren.
    Rueckgabe: (zeilen, terminal). terminal=True heisst: die Zeilen springen selbst weiter,
    der Standard-Sprung auf Funktion+4 darf nicht mehr angehaengt werden.
    """
    word = struct.unpack("<I", bytes(insn.bytes))[0]
    mn, ops = insn.mnemonic, insn.op_str
    va = image_base + rva
    nxt = rva + 4

    if REG1617.search(ops):
        die(f"RVA 0x{rva:x}: erste Instruktion '{mn} {ops}' nutzt x16/x17")

    def to_rva(target_va):
        r = target_va - image_base
        if r < 0 or r > 0xFFFFFFFF:
            die(f"RVA 0x{rva:x}: Ziel 0x{target_va:x} ausserhalb des Bereichs (Instruktion '{mn} {ops}')")
        return r

    lab = f"Lkm_taken_{idx}"

    # b imm26
    if (word >> 26) == 0b000101:
        t = va + sx(word & 0x3ffffff, 26) * 4
        return [f"    KM_JUMP_BASE_PLUS 0x{to_rva(t):x}"], True

    # bl imm26: LR = Funktion+4, danach Sprung auf das Ziel
    if (word >> 26) == 0b100101:
        t = va + sx(word & 0x3ffffff, 26) * 4
        return [f"    KM_LOAD_BASE_PLUS 30, 0x{nxt:x}",
                f"    KM_JUMP_BASE_PLUS 0x{to_rva(t):x}"], True

    # b.cond imm19
    if (word & 0xFF000010) == 0x54000000:
        t = va + sx((word >> 5) & 0x7ffff, 19) * 4
        return [f"    b.{CONDS[word & 0xf]} {lab}",
                f"    KM_JUMP_BASE_PLUS 0x{nxt:x}",
                f"{lab}:",
                f"    KM_JUMP_BASE_PLUS 0x{to_rva(t):x}"], True

    # cbz / cbnz
    if (word & 0x7E000000) == 0x34000000:
        wide = (word >> 31) & 1
        name = "cbnz" if (word >> 24) & 1 else "cbz"
        t = va + sx((word >> 5) & 0x7ffff, 19) * 4
        return [f"    {name} {gpr(word & 0x1f, wide)}, {lab}",
                f"    KM_JUMP_BASE_PLUS 0x{nxt:x}",
                f"{lab}:",
                f"    KM_JUMP_BASE_PLUS 0x{to_rva(t):x}"], True

    # tbz / tbnz
    if (word & 0x7E000000) == 0x36000000:
        b5 = (word >> 31) & 1
        bit = (b5 << 5) | ((word >> 19) & 0x1f)
        name = "tbnz" if (word >> 24) & 1 else "tbz"
        t = va + sx((word >> 5) & 0x3fff, 14) * 4
        return [f"    {name} {gpr(word & 0x1f, b5)}, #{bit}, {lab}",
                f"    KM_JUMP_BASE_PLUS 0x{nxt:x}",
                f"{lab}:",
                f"    KM_JUMP_BASE_PLUS 0x{to_rva(t):x}"], True

    # adr / adrp
    if (word & 0x1F000000) == 0x10000000:
        rd = word & 0x1f
        imm = sx((((word >> 5) & 0x7ffff) << 2) | ((word >> 29) & 3), 21)
        if (word >> 31) & 1:   # adrp
            t = (va & ~0xfff) + (imm << 12)
        else:                  # adr
            t = va + imm
        return [f"    KM_LOAD_BASE_PLUS {rd}, 0x{to_rva(t):x}"], False

    # ldr (literal), auch ldrsw, prfm und SIMD-Varianten
    if (word & 0x3B000000) == 0x18000000:
        opc = (word >> 30) & 3
        simd = (word >> 26) & 1
        rt = word & 0x1f
        t = va + sx((word >> 5) & 0x7ffff, 19) * 4
        if not simd and opc == 3:
            return [f"    // prfm (literal) ignoriert: {mn} {ops}"], False
        if simd:
            if opc == 3:
                die(f"RVA 0x{rva:x}: unbekannte SIMD-Variante von ldr literal '{mn} {ops}'")
            reg = f"{'sdq'[opc]}{rt}"
            op = "ldr"
        elif opc == 0:
            reg, op = gpr(rt, False), "ldr"
        elif opc == 1:
            reg, op = gpr(rt, True), "ldr"
        else:
            reg, op = gpr(rt, True), "ldrsw"
        return [f"    KM_LOAD_BASE_PLUS 16, 0x{to_rva(t):x}",
                f"    {op} {reg}, [x16]"], False

    # alle anderen Instruktionen sind positionsunabhaengig
    return [f"    .inst 0x{word:08x}   // {mn} {ops}"], False


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
        print(f"  {h['name']:<16} RVA 0x{rva:08x}  orig: {insn.mnemonic} {insn.op_str}")
        lines, terminal = displaced_asm(insn, rva, i, image_base)
        asm.append((i, h, lines, terminal))
        c_va, s_va = cave_va + i * CAVE, slot_va + i * 8
        cave_bytes[i * CAVE:(i + 1) * CAVE] = struct.pack(
            "<4I", enc_adrp(16, c_va, s_va), enc_ldr_x(16, 16, s_va & 0xfff), BR_X16, NOP)
        b.patch_address(va, list(struct.pack("<I", enc_b(va, c_va))))
    seg_t.content = list(cave_bytes)

    if b.has_code_signature:
        b.remove_signature()
    b.write(out)
    print("geschrieben:", out)

    with open(f"{dylib_dir}/kitmod_gen.h", "w") as f:
        f.write("// AUTO-GENERIERT von build_hooks.py\n#pragma once\n")
        f.write(f"#define KM_NHOOKS {n}\n#define KM_SLOT_RVA 0x{slot_va - image_base:x}ULL\n")
        f.write("enum { " + ", ".join(f"KM_{h['name']}" for _, h, _, _ in asm) + " };\n")
        f.write("static const uint32_t KM_RVAS[KM_NHOOKS] = {"
                + ", ".join(h["rva"] for _, h, _, _ in asm) + "};\n")
        for i, _, _, _ in asm:
            f.write(f"extern void km_tramp_{i}(void); extern void km_leave_{i}(void);\n")
        f.write("static void *const KM_TRAMPS[KM_NHOOKS] = {"
                + ", ".join(f"km_tramp_{i}" for i, _, _, _ in asm) + "};\n")
        f.write("static void *const KM_LEAVES[KM_NHOOKS] = {"
                + ", ".join(f"km_leave_{i}" for i, _, _, _ in asm) + "};\n")
    with open(f"{dylib_dir}/kitmod_tramp.S", "w") as f:
        f.write(TRAMP_HEAD)
        for i, h, body, terminal in asm:
            rva = int(h["rva"], 16)
            f.write(f"\n// ---- {h['name']} (RVA 0x{rva:x}) ----\n")
            f.write(f".globl _km_tramp_{i}\n.p2align 2\n_km_tramp_{i}:\n"
                    f"    KM_SAVE\n    mov x0, #{i}\n    mov x1, sp\n    bl _kitmod_enter\n"
                    f"    mov x16, x0\n    KM_RESTORE\n    mov x30, x16\n")
            f.write("\n".join(body) + "\n")
            if not terminal:
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
