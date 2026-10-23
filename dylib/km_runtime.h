#pragma once
#include <stdint.h>
#include <stddef.h>
// Startet die QuickJS-Laufzeit in einem eigenen Thread (nach delay_ms), laedt prelude + script.
void km_runtime_start(uint64_t base, const uint32_t *rvas, int nrvas, const char *prelude, size_t plen, const char *script, size_t slen, int delay_ms);
int  km_runtime_start_sync(uint64_t base, const uint32_t *rvas, int nrvas, const char *prelude, size_t plen, const char *script, size_t slen);
int  km_js_ready(void);
// Hook-Einsprung. Rueckgabe 1 = mindestens ein Listener hat onLeave -> Aufrufer biegt LR um und ruft spaeter km_js_leave.
int  km_js_enter(int idx, void *regs, uint64_t token);
void km_js_leave(int idx, void *regs, uint64_t token);
