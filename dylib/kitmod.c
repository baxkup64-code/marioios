// kitmod.c -- Verbindung zwischen den statisch gepatchten Hooks (kitmod_tramp.S) und der QuickJS-Laufzeit (km_runtime.c).
// Das Skript selbst (debug_ios.ts -> script.js) laeuft unveraendert in der Laufzeit.
#include <stdint.h>
#include <string.h>
#include <mach-o/dyld.h>
#include "kitmod_gen.h"   // von tools/build_hooks.py erzeugt
#include "km_runtime.h"

extern const unsigned char km_prelude[]; extern const unsigned long km_prelude_len;
extern const unsigned char km_script[];  extern const unsigned long km_script_len;

// Frame-Layout wie in kitmod_tramp.S: x0..x8, x29, x30, d0..d7 (0xA0 Byte)
typedef struct { uint64_t x[9]; uint64_t fp, lr; double d[8]; } km_regs;
_Static_assert(sizeof(km_regs) == 152, "km_regs-Layout");

uint64_t kitmod_base;                              // von kitmod_tramp.S gelesen

typedef struct { uint64_t lr, token; } Shadow;
static __thread Shadow t_sh[64];
static __thread int t_sp;
static volatile uint64_t g_token;

uint64_t kitmod_enter(int idx, km_regs *r) {
    if (km_js_ready() && t_sp < 64) {
        uint64_t tok = __sync_add_and_fetch(&g_token, 1);
        if (km_js_enter(idx, r, tok)) {            // mindestens ein onLeave-Listener -> LR umbiegen
            t_sh[t_sp].lr = r->lr; t_sh[t_sp].token = tok; t_sp++;
            return (uint64_t)KM_LEAVES[idx];
        }
    }
    return r->lr;
}
uint64_t kitmod_leave(int idx, km_regs *r) {       // r->x[0] = Rueckgabewert
    if (t_sp <= 0) return 0;
    Shadow e = t_sh[--t_sp];
    km_js_leave(idx, r, e.token);
    return e.lr;
}

__attribute__((constructor)) static void kitmod_init(void) {
    kitmod_base = (uint64_t)_dyld_get_image_header(0);        // Hauptprogramm = Process.mainModule.base
    volatile uint64_t *slots = (volatile uint64_t *)(kitmod_base + KM_SLOT_RVA);
    for (int i = 0; i < KM_NHOOKS; i++) slots[i] = (uint64_t)KM_TRAMPS[i];   // reine Daten-Writes, kein JIT
    // Skript erst nach dem App-Start laden (3 s), analog zum Gadget im Frida-Betrieb
    km_runtime_start(kitmod_base, KM_RVAS, KM_NHOOKS, (const char *)km_prelude, km_prelude_len, (const char *)km_script, km_script_len, 3000);
}
