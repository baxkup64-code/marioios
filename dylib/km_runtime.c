// km_runtime.c -- Frida-kompatible Mini-Laufzeit auf QuickJS (reiner Interpreter, KEIN JIT).
// Stellt genau die API bereit, die debug_ios.ts benutzt: ptr/NativePointer, Memory, NativeFunction, NativeCallback,
// Interceptor.attach (auf vorgepatchte Stellen), Process, Module, File, console, setTimeout/setInterval.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>
#include <time.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include "quickjs.h"
#include "km_runtime.h"
#ifdef __APPLE__
#include <mach/mach.h>
#include <os/log.h>
#endif

typedef uint64_t u64;

// ------------------------------------------------------------------ Logging
static FILE *g_logf;
static void km_log(const char *s) {
#ifdef __APPLE__
    os_log(OS_LOG_DEFAULT, "[KITMOD] %{public}s", s);
#else
    fprintf(stderr, "[KITMOD] %s\n", s);
#endif
    if (g_logf) { fprintf(g_logf, "%s\n", s); fflush(g_logf); }
}
static void log_open(void) {
    const char *home = getenv("HOME");
    if (!home) return;
    char path[1024];
    snprintf(path, sizeof path, "%s/Documents/kitmod.log", home);
    long sz = 0; FILE *t = fopen(path, "r");
    if (t) { fseek(t, 0, SEEK_END); sz = ftell(t); fclose(t); }
    g_logf = fopen(path, sz > (1 << 20) ? "w" : "a");
}

// ------------------------------------------------------------------ globale Zustaende
static JSRuntime *rt;
static JSContext *ctx;
static pthread_mutex_t g_lock;               // rekursiv: serialisiert ALLES JS (wie Frida's globaler Lock)
static volatile int g_ready;
static u64 g_base;
static const uint32_t *g_rvas; static int g_nrvas;
static JSValue g_enter_fn = JS_UNDEFINED, g_leave_fn = JS_UNDEFINED, g_timer_fn = JS_UNDEFINED;

static void lock_js(void) { pthread_mutex_lock(&g_lock); JS_UpdateStackTop(rt); }
static void unlock_js(void) { pthread_mutex_unlock(&g_lock); }

static void dump_exc(JSContext *c) {
    JSValue e = JS_GetException(c);
    const char *s = JS_ToCString(c, e);
    JSValue st = JS_GetPropertyStr(c, e, "stack");
    const char *ss = JS_IsUndefined(st) ? NULL : JS_ToCString(c, st);
    char buf[4096]; snprintf(buf, sizeof buf, "JS-Fehler: %s%s%s", s ? s : "?", ss ? "\n" : "", ss ? ss : "");
    km_log(buf);
    if (ss) JS_FreeCString(c, ss);
    if (s) JS_FreeCString(c, s);
    JS_FreeValue(c, st); JS_FreeValue(c, e);
}
static void run_jobs(void) { JSContext *c; while (JS_ExecutePendingJob(rt, &c) > 0) {} }

// ------------------------------------------------------------------ sicherer Speicherzugriff (SIGSEGV/SIGBUS -> JS-Exception)
static __thread sigjmp_buf *t_jb;
static struct sigaction old_segv, old_bus;
static void fault_handler(int sig, siginfo_t *si, void *uc) {
    if (t_jb) siglongjmp(*t_jb, 1);
    struct sigaction *o = sig == SIGSEGV ? &old_segv : &old_bus;
    if (o->sa_flags & SA_SIGINFO) { if (o->sa_sigaction) { o->sa_sigaction(sig, si, uc); return; } }
    else if (o->sa_handler != SIG_DFL && o->sa_handler != SIG_IGN && o->sa_handler) { o->sa_handler(sig); return; }
    signal(sig, SIG_DFL);
}
static void install_fault_handlers(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = fault_handler; sa.sa_flags = SA_SIGINFO | SA_NODEFER; sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv); sigaction(SIGBUS, &sa, &old_bus);
}
static int safe_copy(void *dst, const void *src, size_t n) {
    sigjmp_buf jb; sigjmp_buf *prev = t_jb;
    if (sigsetjmp(jb, 0)) { t_jb = prev; return -1; }
    t_jb = &jb; __asm__ volatile("" ::: "memory");   // Barriere: Store von t_jb darf nicht hinter den Zugriff rutschen
    volatile const unsigned char *s = src; volatile unsigned char *d = dst;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    __asm__ volatile("" ::: "memory"); t_jb = prev;
    return 0;
}
static JSValue throw_av(JSContext *c, u64 a) { return JS_ThrowPlainError(c, "access violation accessing 0x%llx", (unsigned long long)a); }

// ------------------------------------------------------------------ NativePointer
typedef struct { u64 a; void *own; int cb; } NP;
static JSClassID np_class, sig_class;
static JSValue np_proto;
static void cb_release(JSRuntime *r, int slot);
static void np_fin(JSRuntime *r, JSValue v) {
    NP *p = JS_GetOpaque(v, np_class);
    if (!p) return;
    if (p->own) free(p->own);
    if (p->cb > 0) cb_release(r, p->cb - 1);
    free(p);
}
static JSClassDef np_def = { "NativePointer", .finalizer = np_fin };
static JSValue np_new(JSContext *c, u64 a) {
    JSValue o = JS_NewObjectClass(c, np_class);
    if (JS_IsException(o)) return o;
    NP *p = calloc(1, sizeof(NP)); p->a = a; JS_SetOpaque(o, p);
    return o;
}
static NP *np_get(JSValueConst v) { return JS_GetOpaque(v, np_class); }
static int to_u64(JSContext *c, JSValueConst v, u64 *out) {
    NP *p = np_get(v);
    if (p) { *out = p->a; return 0; }
    if (JS_IsUndefined(v) || JS_IsNull(v)) { *out = 0; return 0; }
    if (JS_IsString(v)) {
        const char *s = JS_ToCString(c, v); if (!s) return -1;
        *out = strtoull(s, NULL, (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? 16 : 10);
        JS_FreeCString(c, s); return 0;
    }
    if (JS_IsBigInt(v)) { return JS_ToBigUint64(c, out, v); }
    if (JS_IsBool(v)) { *out = JS_ToBool(c, v); return 0; }
    int64_t i; if (JS_ToInt64Ext(c, &i, v)) return -1;
    *out = (u64)i; return 0;
}
static JSValue num_or_big(JSContext *c, u64 v, int is_signed) {
    if (is_signed) { int64_t s = (int64_t)v; return (s > -(1LL << 53) && s < (1LL << 53)) ? JS_NewInt64(c, s) : JS_NewBigInt64(c, s); }
    return v < (1ULL << 53) ? JS_NewInt64(c, (int64_t)v) : JS_NewBigUint64(c, v);
}
#define SELF(var) NP *var = np_get(this_val); if (!var) return JS_ThrowTypeError(c, "kein NativePointer")
#define ARG_U64(i, var) u64 var = 0; if (argc > (i) && to_u64(c, argv[i], &var)) return JS_EXCEPTION

static JSValue js_ptr(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) { ARG_U64(0, v); return np_new(c, v); }
enum { OP_ADD, OP_SUB, OP_AND, OP_OR, OP_XOR, OP_SHL, OP_SHR };
static JSValue np_op(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv, int m) {
    SELF(p); ARG_U64(0, b); u64 a = p->a, r = 0;
    switch (m) {
    case OP_ADD: r = a + b; break; case OP_SUB: r = a - b; break; case OP_AND: r = a & b; break;
    case OP_OR: r = a | b; break; case OP_XOR: r = a ^ b; break; case OP_SHL: r = b > 63 ? 0 : a << b; break;
    case OP_SHR: r = b > 63 ? 0 : a >> b; break;
    }
    return np_new(c, r);
}
static JSValue np_not(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv) { SELF(p); return np_new(c, ~p->a); }
static JSValue np_isnull(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv) { SELF(p); return JS_NewBool(c, p->a == 0); }
static JSValue np_equals(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv) { SELF(p); ARG_U64(0, b); return JS_NewBool(c, p->a == b); }
static JSValue np_compare(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv) { SELF(p); ARG_U64(0, b); return JS_NewInt32(c, p->a < b ? -1 : p->a > b ? 1 : 0); }
static JSValue np_tostring(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv) {
    SELF(p); int radix = 16;
    if (argc > 0 && !JS_IsUndefined(argv[0])) JS_ToInt32(c, &radix, argv[0]);
    char b[40]; if (radix == 10) snprintf(b, sizeof b, "%llu", (unsigned long long)p->a); else snprintf(b, sizeof b, "0x%llx", (unsigned long long)p->a);
    return JS_NewString(c, b);
}
static JSValue np_toint32(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv) { SELF(p); return JS_NewInt32(c, (int32_t)p->a); }
static JSValue np_touint32(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv) { SELF(p); return JS_NewUint32(c, (uint32_t)p->a); }
static JSValue np_tonumber(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv) { SELF(p); return JS_NewFloat64(c, (double)p->a); }

// ---- read*/write*
enum { T_S8, T_U8, T_S16, T_U16, T_S32, T_U32, T_S64, T_U64, T_PTR, T_F32, T_F64 };
static const int tsize[] = { 1, 1, 2, 2, 4, 4, 8, 8, 8, 4, 8 };
static JSValue np_read(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv, int m) {
    SELF(p); unsigned char buf[8] = { 0 };
    if (safe_copy(buf, (void *)(uintptr_t)p->a, tsize[m])) return throw_av(c, p->a);
    switch (m) {
    case T_S8: return JS_NewInt32(c, *(int8_t *)buf); case T_U8: return JS_NewInt32(c, *(uint8_t *)buf);
    case T_S16: { int16_t v; memcpy(&v, buf, 2); return JS_NewInt32(c, v); }
    case T_U16: { uint16_t v; memcpy(&v, buf, 2); return JS_NewInt32(c, v); }
    case T_S32: { int32_t v; memcpy(&v, buf, 4); return JS_NewInt32(c, v); }
    case T_U32: { uint32_t v; memcpy(&v, buf, 4); return JS_NewUint32(c, v); }
    case T_S64: { u64 v; memcpy(&v, buf, 8); return num_or_big(c, v, 1); }
    case T_U64: { u64 v; memcpy(&v, buf, 8); return num_or_big(c, v, 0); }
    case T_PTR: { u64 v; memcpy(&v, buf, 8); return np_new(c, v); }
    case T_F32: { float v; memcpy(&v, buf, 4); return JS_NewFloat64(c, v); }
    default: { double v; memcpy(&v, buf, 8); return JS_NewFloat64(c, v); }
    }
}
static JSValue np_write(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv, int m) {
    SELF(p); unsigned char buf[8] = { 0 };
    if (argc < 1) return JS_ThrowTypeError(c, "Wert fehlt");
    if (m == T_F32) { double d; if (JS_ToFloat64(c, &d, argv[0])) return JS_EXCEPTION; float f = (float)d; memcpy(buf, &f, 4); }
    else if (m == T_F64) { double d; if (JS_ToFloat64(c, &d, argv[0])) return JS_EXCEPTION; memcpy(buf, &d, 8); }
    else { u64 v; if (to_u64(c, argv[0], &v)) return JS_EXCEPTION; memcpy(buf, &v, tsize[m]); }   // little endian
    if (safe_copy((void *)(uintptr_t)p->a, buf, tsize[m])) return throw_av(c, p->a);
    return JS_DupValue(c, this_val);
}
static JSValue np_read_utf8(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv) {
    SELF(p); const char *src = (const char *)(uintptr_t)p->a;
    if (argc > 0 && !JS_IsUndefined(argv[0])) {
        int32_t n; JS_ToInt32(c, &n, argv[0]);
        if (n < 0) n = 0;
        char *b = malloc(n + 1);
        if (safe_copy(b, src, n)) { free(b); return throw_av(c, p->a); }
        JSValue r = JS_NewStringLen(c, b, n); free(b); return r;
    }
    size_t cap = 256, n = 0; char *b = malloc(cap);
    sigjmp_buf jb; sigjmp_buf *prev = t_jb;
    if (sigsetjmp(jb, 0)) { t_jb = prev; free(b); return throw_av(c, p->a + n); }
    t_jb = &jb; __asm__ volatile("" ::: "memory");
    for (;;) {
        char ch = ((volatile const char *)src)[n];
        if (n + 2 > cap && cap < (1u << 24)) { cap *= 2; b = realloc(b, cap); }
        if (ch == 0 || n + 2 > cap) break;
        b[n++] = ch;
    }
    __asm__ volatile("" ::: "memory"); t_jb = prev;
    JSValue r = JS_NewStringLen(c, b, n); free(b); return r;
}
static JSValue np_read_bytes(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv) {
    SELF(p); uint64_t n = 0; if (argc > 0 && JS_ToIndex(c, &n, argv[0])) return JS_EXCEPTION;
    uint8_t *b = malloc(n ? n : 1);
    if (safe_copy(b, (void *)(uintptr_t)p->a, n)) { free(b); return throw_av(c, p->a); }
    JSValue r = JS_NewArrayBufferCopy(c, b, n); free(b); return r;
}
static JSValue np_write_utf8(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv) {
    SELF(p); size_t n; const char *s = JS_ToCStringLen(c, &n, argv[0]); if (!s) return JS_EXCEPTION;
    int bad = safe_copy((void *)(uintptr_t)p->a, s, n + 1); JS_FreeCString(c, s);
    return bad ? throw_av(c, p->a) : JS_DupValue(c, this_val);
}
static JSValue np_write_bytes(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv) {
    SELF(p); size_t n = 0; uint8_t *src = JS_GetArrayBuffer(c, &n, argv[0]);
    uint8_t *tmp = NULL;
    if (!src) {
        JS_FreeValue(c, JS_GetException(c));
        size_t off = 0, len = 0, bpe = 0; JSValue ab = JS_GetTypedArrayBuffer(c, argv[0], &off, &len, &bpe);
        if (!JS_IsException(ab)) { size_t sz; uint8_t *base = JS_GetArrayBuffer(c, &sz, ab); src = base ? base + off : NULL; n = len; JS_FreeValue(c, ab); }
        else {
            JS_FreeValue(c, JS_GetException(c));
            JSValue lv = JS_GetPropertyStr(c, argv[0], "length"); uint32_t l = 0; JS_ToUint32(c, &l, lv); JS_FreeValue(c, lv);
            tmp = malloc(l ? l : 1);
            for (uint32_t i = 0; i < l; i++) { JSValue e = JS_GetPropertyUint32(c, argv[0], i); int32_t v = 0; JS_ToInt32(c, &v, e); JS_FreeValue(c, e); tmp[i] = (uint8_t)v; }
            src = tmp; n = l;
        }
    }
    int bad = safe_copy((void *)(uintptr_t)p->a, src, n); free(tmp);
    return bad ? throw_av(c, p->a) : JS_DupValue(c, this_val);
}

// ------------------------------------------------------------------ Memory / Process / Module / File (Natives)
static JSValue np_own(JSContext *c, void *mem) { JSValue o = np_new(c, (u64)(uintptr_t)mem); NP *p = np_get(o); p->own = mem; return o; }
static JSValue n_alloc(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {
    uint64_t n = 0; if (argc > 0 && JS_ToIndex(c, &n, argv[0])) return JS_EXCEPTION;
    void *m = calloc(1, (n + 15) & ~15ULL ? (n + 15) & ~15ULL : 16); return np_own(c, m);
}
static JSValue n_alloc_utf8(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {
    size_t n; const char *s = JS_ToCStringLen(c, &n, argv[0]); if (!s) return JS_EXCEPTION;
    char *m = calloc(1, n + 16); memcpy(m, s, n); JS_FreeCString(c, s); return np_own(c, m);
}
static JSValue n_copy(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {
    u64 d, s; uint64_t n; if (to_u64(c, argv[0], &d) || to_u64(c, argv[1], &s) || JS_ToIndex(c, &n, argv[2])) return JS_EXCEPTION;
    uint8_t *tmp = malloc(n ? n : 1);
    int bad = safe_copy(tmp, (void *)(uintptr_t)s, n) || safe_copy((void *)(uintptr_t)d, tmp, n); free(tmp);
    return bad ? throw_av(c, s) : JS_UNDEFINED;
}
static JSValue n_range(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {   // Process.findRangeByAddress
    u64 a; if (to_u64(c, argv[0], &a)) return JS_EXCEPTION;
#ifdef __APPLE__
    vm_address_t addr = (vm_address_t)a; vm_size_t sz = 0; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64; mach_port_t obj;
    kern_return_t kr = vm_region_64(mach_task_self(), &addr, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj);
    if (kr != KERN_SUCCESS || addr > (vm_address_t)a || !(info.protection & VM_PROT_READ)) return JS_NULL;
    JSValue o = JS_NewObject(c);
    JS_SetPropertyStr(c, o, "base", np_new(c, addr)); JS_SetPropertyStr(c, o, "size", JS_NewInt64(c, sz));
    char pr[4] = { (info.protection & VM_PROT_READ) ? 'r' : '-', (info.protection & VM_PROT_WRITE) ? 'w' : '-', (info.protection & VM_PROT_EXECUTE) ? 'x' : '-', 0 };
    JS_SetPropertyStr(c, o, "protection", JS_NewString(c, pr));
    return o;
#else
    unsigned char b; if (safe_copy(&b, (void *)(uintptr_t)a, 1)) return JS_NULL;
    JSValue o = JS_NewObject(c); JS_SetPropertyStr(c, o, "base", np_new(c, a & ~0xfffULL)); JS_SetPropertyStr(c, o, "size", JS_NewInt32(c, 4096));
    JS_SetPropertyStr(c, o, "protection", JS_NewString(c, "r--")); return o;
#endif
}
static JSValue n_dlsym(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {
    const char *s = JS_ToCString(c, argv[0]); if (!s) return JS_EXCEPTION;
    void *p = dlsym(RTLD_DEFAULT, s); JS_FreeCString(c, s);
    return p ? np_new(c, (u64)(uintptr_t)p) : JS_NULL;
}
static JSValue n_readfile(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {
    const char *s = JS_ToCString(c, argv[0]); if (!s) return JS_EXCEPTION;
    FILE *f = fopen(s, "rb"); if (!f) { JSValue e = JS_ThrowPlainError(c, "Datei nicht lesbar: %s", s); JS_FreeCString(c, s); return e; }
    JS_FreeCString(c, s);
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = malloc(n + 1); size_t r = fread(b, 1, n, f); fclose(f);
    JSValue v = JS_NewStringLen(c, b, r); free(b); return v;
}
static JSValue n_log(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {
    const char *s = JS_ToCString(c, argv[0]); if (s) { km_log(s); JS_FreeCString(c, s); } return JS_UNDEFINED;
}
static JSValue n_base(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) { return np_new(c, g_base); }
static JSValue n_hookindex(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {
    u64 a; if (to_u64(c, argv[0], &a)) return JS_EXCEPTION;
    u64 rva = a - g_base;
    for (int i = 0; i < g_nrvas; i++) if (g_rvas[i] == rva) return JS_NewInt32(c, i);
    return JS_NewInt32(c, -1);
}
static JSValue n_regget(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {   // Register i aus dem Hook-Frame
    int64_t r; int32_t i; JS_ToInt64Ext(c, &r, argv[0]); JS_ToInt32(c, &i, argv[1]);
    return np_new(c, ((u64 *)(uintptr_t)r)[i]);
}
static JSValue n_regset(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {
    int64_t r; int32_t i; u64 v; JS_ToInt64Ext(c, &r, argv[0]); JS_ToInt32(c, &i, argv[1]);
    if (to_u64(c, argv[2], &v)) return JS_EXCEPTION;
    ((u64 *)(uintptr_t)r)[i] = v; return JS_UNDEFINED;
}

// ------------------------------------------------------------------ NativeFunction (ohne libffi: AAPCS64 - Int-Register x0-x7 und FP-Register d0-d7 getrennt)
enum { K_VOID, K_PTR, K_I8, K_U8, K_I16, K_U16, K_I32, K_U32, K_I64, K_U64, K_F32, K_F64, K_BOOL, K_HFA };
// K_HFA: Struktur aus 1-4 gleichen float/double-Feldern (z.B. CGRect) -> AAPCS64: je Feld ein FP-Register
typedef struct { u64 addr; int ret, n, at[16], hn[16], hk[16]; } Sig;
static void sig_fin(JSRuntime *r, JSValue v) { free(JS_GetOpaque(v, sig_class)); }
static JSClassDef sig_def = { "KmSig", .finalizer = sig_fin };
static int kind_of(JSContext *c, JSValueConst v);
static int kind_hfa(JSContext *c, JSValueConst v, int *hn, int *hk) {
    JSValue lv = JS_GetPropertyStr(c, v, "length"); uint32_t n = 0; JS_ToUint32(c, &n, lv); JS_FreeValue(c, lv);
    if (n < 1 || n > 4) { JS_ThrowTypeError(c, "Struktur-Typ: nur 1-4 float/double-Felder unterstuetzt"); return -1; }
    for (uint32_t i = 0; i < n; i++) {
        JSValue e = JS_GetPropertyUint32(c, v, i); int k = kind_of(c, e); JS_FreeValue(c, e);
        if (k != K_F32 && k != K_F64) { if (k >= 0) JS_ThrowTypeError(c, "Struktur-Typ: nur float/double-Felder unterstuetzt"); return -1; }
        if (i == 0) *hk = k; else if (*hk != k) { JS_ThrowTypeError(c, "Struktur-Typ: gemischte Felder"); return -1; }
    }
    *hn = n; return K_HFA;
}
static int kind_of(JSContext *c, JSValueConst v) {
    if (JS_IsArray(v)) { int hn, hk; return kind_hfa(c, v, &hn, &hk); }
    const char *s = JS_ToCString(c, v); if (!s) return -1; int k = -1;
    static const struct { const char *n; int k; } T[] = {
        {"void", K_VOID}, {"pointer", K_PTR}, {"int", K_I32}, {"uint", K_U32}, {"long", K_I64}, {"ulong", K_U64},
        {"int8", K_I8}, {"uint8", K_U8}, {"int16", K_I16}, {"uint16", K_U16}, {"int32", K_I32}, {"uint32", K_U32},
        {"int64", K_I64}, {"uint64", K_U64}, {"float", K_F32}, {"double", K_F64}, {"bool", K_BOOL}, {"char", K_I8},
        {"uchar", K_U8}, {"short", K_I16}, {"ushort", K_U16}, {"size_t", K_U64}, {"ssize_t", K_I64}, {"bytes", K_U64} };
    for (size_t i = 0; i < sizeof T / sizeof T[0]; i++) if (!strcmp(T[i].n, s)) { k = T[i].k; break; }
    if (k < 0) JS_ThrowTypeError(c, "unbekannter Typ: %s", s);
    JS_FreeCString(c, s); return k;
}
typedef u64 (*F_I)(u64, u64, u64, u64, u64, u64, u64, u64, double, double, double, double, double, double, double, double);
typedef double (*F_D)(u64, u64, u64, u64, u64, u64, u64, u64, double, double, double, double, double, double, double, double);
typedef float (*F_F)(u64, u64, u64, u64, u64, u64, u64, u64, double, double, double, double, double, double, double, double);

static JSValue from_raw(JSContext *c, int k, u64 x) {
    switch (k) {
    case K_VOID: return JS_UNDEFINED; case K_PTR: return np_new(c, x);
    case K_I8: return JS_NewInt32(c, (int8_t)x); case K_U8: return JS_NewInt32(c, (uint8_t)x);
    case K_I16: return JS_NewInt32(c, (int16_t)x); case K_U16: return JS_NewInt32(c, (uint16_t)x);
    case K_I32: return JS_NewInt32(c, (int32_t)x); case K_U32: return JS_NewUint32(c, (uint32_t)x);
    case K_I64: return num_or_big(c, x, 1); case K_U64: return num_or_big(c, x, 0);
    case K_BOOL: return JS_NewBool(c, (x & 0xff) != 0);
    }
    return JS_UNDEFINED;
}
static JSValue nfn_call(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv, int magic, JSValueConst *fd) {
    Sig *s = JS_GetOpaque(fd[0], sig_class);
    if (argc < s->n) return JS_ThrowTypeError(c, "falsche Argumentanzahl (erwartet %d)", s->n);
    u64 xi[8] = { 0 }; double xd[8] = { 0 }; int ni = 0, nd = 0;
    for (int i = 0; i < s->n; i++) {
        int k = s->at[i];
        if (k == K_HFA) {
            if (nd + s->hn[i] > 8) return JS_ThrowTypeError(c, "zu viele FP-Argumente");
            for (int j = 0; j < s->hn[i]; j++) {
                JSValue e = JS_GetPropertyUint32(c, argv[i], j); double d = 0; int rc = JS_ToFloat64(c, &d, e); JS_FreeValue(c, e); if (rc) return JS_EXCEPTION;
                if (s->hk[i] == K_F32) { float f = (float)d; u64 u = 0; memcpy(&u, &f, 4); memcpy(&xd[nd++], &u, 8); } else xd[nd++] = d;
            }
        } else if (k == K_F32 || k == K_F64) {
            double d; if (JS_ToFloat64(c, &d, argv[i])) return JS_EXCEPTION;
            if (nd >= 8) return JS_ThrowTypeError(c, "zu viele FP-Argumente");
            if (k == K_F32) { float f = (float)d; u64 u = 0; memcpy(&u, &f, 4); memcpy(&xd[nd++], &u, 8); } else xd[nd++] = d;
        } else {
            u64 v; if (ni >= 8) return JS_ThrowTypeError(c, "zu viele Int-Argumente (max. 8)");
            if (k == K_BOOL) v = JS_ToBool(c, argv[i]) ? 1 : 0; else if (to_u64(c, argv[i], &v)) return JS_EXCEPTION;
            xi[ni++] = v;
        }
    }
    void *fn = (void *)(uintptr_t)s->addr;
    if (s->ret == K_F64) { double r = ((F_D)fn)(xi[0], xi[1], xi[2], xi[3], xi[4], xi[5], xi[6], xi[7], xd[0], xd[1], xd[2], xd[3], xd[4], xd[5], xd[6], xd[7]); return JS_NewFloat64(c, r); }
    if (s->ret == K_F32) { float r = ((F_F)fn)(xi[0], xi[1], xi[2], xi[3], xi[4], xi[5], xi[6], xi[7], xd[0], xd[1], xd[2], xd[3], xd[4], xd[5], xd[6], xd[7]); return JS_NewFloat64(c, r); }
    u64 r = ((F_I)fn)(xi[0], xi[1], xi[2], xi[3], xi[4], xi[5], xi[6], xi[7], xd[0], xd[1], xd[2], xd[3], xd[4], xd[5], xd[6], xd[7]);
    return from_raw(c, s->ret, r);
}
static int parse_sig(JSContext *c, JSValueConst ret, JSValueConst args, Sig *s) {
    s->ret = kind_of(c, ret); if (s->ret < 0) return -1;
    JSValue lv = JS_GetPropertyStr(c, args, "length"); uint32_t n = 0; JS_ToUint32(c, &n, lv); JS_FreeValue(c, lv);
    if (n > 16) { JS_ThrowTypeError(c, "zu viele Argumente"); return -1; }
    s->n = n;
    for (uint32_t i = 0; i < n; i++) {
        JSValue e = JS_GetPropertyUint32(c, args, i);
        s->at[i] = JS_IsArray(e) ? kind_hfa(c, e, &s->hn[i], &s->hk[i]) : kind_of(c, e);
        JS_FreeValue(c, e); if (s->at[i] < 0) return -1;
    }
    if (s->ret == K_HFA) { JS_ThrowTypeError(c, "Struktur als Rueckgabewert nicht unterstuetzt"); return -1; }
    return 0;
}
static JSValue n_nfn(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {   // __nfn(addr, ret, args)
    u64 a; if (to_u64(c, argv[0], &a)) return JS_EXCEPTION;
    if (!a) return JS_ThrowTypeError(c, "NativeFunction: Adresse ist 0 / Symbol nicht gefunden");
    Sig *s = calloc(1, sizeof(Sig)); s->addr = a;
    if (parse_sig(c, argv[1], argv[2], s)) { free(s); return JS_EXCEPTION; }
    JSValue so = JS_NewObjectClass(c, sig_class); JS_SetOpaque(so, s);
    JSValue f = JS_NewCFunctionData(c, nfn_call, 0, 0, 1, &so); JS_FreeValue(c, so); return f;
}

// ------------------------------------------------------------------ NativeCallback: statischer Stub-Pool (kein Code zur Laufzeit)
typedef struct { int used; JSValue fn; Sig sig; } CB;
#define NCB 96
static CB g_cb[NCB];
static u64 cb_dispatch(int slot, u64 *x, double *d) {
    CB *cb = &g_cb[slot]; u64 ret = 0;
    if (!g_ready || !cb->used) return 0;
    lock_js();
    JSValue av[16]; int ni = 0, nd = 0;
    for (int i = 0; i < cb->sig.n; i++) {
        int k = cb->sig.at[i];
        if (k == K_F32) { float f; u64 u; memcpy(&u, &d[nd++], 8); uint32_t lo = (uint32_t)u; memcpy(&f, &lo, 4); av[i] = JS_NewFloat64(ctx, f); }
        else if (k == K_F64) av[i] = JS_NewFloat64(ctx, d[nd++]);
        else av[i] = from_raw(ctx, k, ni < 8 ? x[ni++] : 0);
    }
    JSValue r = JS_Call(ctx, cb->fn, JS_UNDEFINED, cb->sig.n, av);
    for (int i = 0; i < cb->sig.n; i++) JS_FreeValue(ctx, av[i]);
    if (JS_IsException(r)) dump_exc(ctx);
    else { if (cb->sig.ret != K_VOID && cb->sig.ret != K_F32 && cb->sig.ret != K_F64) { if (cb->sig.ret == K_BOOL) ret = JS_ToBool(ctx, r) ? 1 : 0; else to_u64(ctx, r, &ret); } JS_FreeValue(ctx, r); }
    run_jobs(); unlock_js();
    return ret;
}
#define STUB(N) static u64 km_stub_##N(u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7, double d0, double d1, double d2, double d3, double d4, double d5, double d6, double d7) { u64 x[8] = { a0, a1, a2, a3, a4, a5, a6, a7 }; double d[8] = { d0, d1, d2, d3, d4, d5, d6, d7 }; return cb_dispatch(N, x, d); }
#define S8(B) STUB(B##0) STUB(B##1) STUB(B##2) STUB(B##3) STUB(B##4) STUB(B##5) STUB(B##6) STUB(B##7) STUB(B##8) STUB(B##9) STUB(B##10) STUB(B##11)
STUB(0) STUB(1) STUB(2) STUB(3) STUB(4) STUB(5) STUB(6) STUB(7) STUB(8) STUB(9)
STUB(10) STUB(11) STUB(12) STUB(13) STUB(14) STUB(15) STUB(16) STUB(17) STUB(18) STUB(19)
STUB(20) STUB(21) STUB(22) STUB(23) STUB(24) STUB(25) STUB(26) STUB(27) STUB(28) STUB(29)
STUB(30) STUB(31) STUB(32) STUB(33) STUB(34) STUB(35) STUB(36) STUB(37) STUB(38) STUB(39)
STUB(40) STUB(41) STUB(42) STUB(43) STUB(44) STUB(45) STUB(46) STUB(47) STUB(48) STUB(49)
STUB(50) STUB(51) STUB(52) STUB(53) STUB(54) STUB(55) STUB(56) STUB(57) STUB(58) STUB(59)
STUB(60) STUB(61) STUB(62) STUB(63) STUB(64) STUB(65) STUB(66) STUB(67) STUB(68) STUB(69)
STUB(70) STUB(71) STUB(72) STUB(73) STUB(74) STUB(75) STUB(76) STUB(77) STUB(78) STUB(79)
STUB(80) STUB(81) STUB(82) STUB(83) STUB(84) STUB(85) STUB(86) STUB(87) STUB(88) STUB(89)
STUB(90) STUB(91) STUB(92) STUB(93) STUB(94) STUB(95)
#define P(N) (void *)km_stub_##N
static void *const g_stubs[NCB] = {
    P(0), P(1), P(2), P(3), P(4), P(5), P(6), P(7), P(8), P(9), P(10), P(11), P(12), P(13), P(14), P(15), P(16), P(17), P(18), P(19),
    P(20), P(21), P(22), P(23), P(24), P(25), P(26), P(27), P(28), P(29), P(30), P(31), P(32), P(33), P(34), P(35), P(36), P(37), P(38), P(39),
    P(40), P(41), P(42), P(43), P(44), P(45), P(46), P(47), P(48), P(49), P(50), P(51), P(52), P(53), P(54), P(55), P(56), P(57), P(58), P(59),
    P(60), P(61), P(62), P(63), P(64), P(65), P(66), P(67), P(68), P(69), P(70), P(71), P(72), P(73), P(74), P(75), P(76), P(77), P(78), P(79),
    P(80), P(81), P(82), P(83), P(84), P(85), P(86), P(87), P(88), P(89), P(90), P(91), P(92), P(93), P(94), P(95) };
static void cb_release(JSRuntime *r, int slot) {
    if (slot < 0 || slot >= NCB || !g_cb[slot].used) return;
    g_cb[slot].used = 0; JS_FreeValueRT(r, g_cb[slot].fn); g_cb[slot].fn = JS_UNDEFINED;
}
static JSValue n_ncb(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {   // __ncb(fn, ret, args)
    int slot = -1; for (int i = 0; i < NCB; i++) if (!g_cb[i].used) { slot = i; break; }
    if (slot < 0) return JS_ThrowPlainError(c, "NativeCallback-Pool erschoepft (%d)", NCB);
    memset(&g_cb[slot].sig, 0, sizeof(Sig));
    if (parse_sig(c, argv[1], argv[2], &g_cb[slot].sig)) return JS_EXCEPTION;
    for (int i = 0; i < g_cb[slot].sig.n; i++) if (g_cb[slot].sig.at[i] == K_HFA) return JS_ThrowTypeError(c, "Struktur-Argumente in NativeCallback nicht unterstuetzt");
    g_cb[slot].fn = JS_DupValue(c, argv[0]); g_cb[slot].used = 1;
    JSValue o = np_new(c, (u64)(uintptr_t)g_stubs[slot]); np_get(o)->cb = slot + 1; return o;
}

// ------------------------------------------------------------------ Timer-Thread
typedef struct Timer { int id; double due; int repeat; double ms; struct Timer *next; } Timer;
static Timer *g_timers; static pthread_mutex_t tm_lock = PTHREAD_MUTEX_INITIALIZER; static pthread_cond_t tm_cond = PTHREAD_COND_INITIALIZER;
static double now_ms(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6; }
static void tm_insert(Timer *t) { Timer **pp = &g_timers; while (*pp && (*pp)->due <= t->due) pp = &(*pp)->next; t->next = *pp; *pp = t; }
static JSValue n_tmset(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {
    int32_t id, rep; double ms; JS_ToInt32(c, &id, argv[0]); JS_ToFloat64(c, &ms, argv[1]); JS_ToInt32(c, &rep, argv[2]);
    if (ms < 1) ms = 1;
    Timer *tm = calloc(1, sizeof *tm); tm->id = id; tm->ms = ms; tm->repeat = rep; tm->due = now_ms() + ms;
    pthread_mutex_lock(&tm_lock); tm_insert(tm); pthread_cond_signal(&tm_cond); pthread_mutex_unlock(&tm_lock);
    return JS_UNDEFINED;
}
static JSValue n_tmclear(JSContext *c, JSValueConst t, int argc, JSValueConst *argv) {
    int32_t id; JS_ToInt32(c, &id, argv[0]);
    pthread_mutex_lock(&tm_lock);
    for (Timer **pp = &g_timers; *pp; pp = &(*pp)->next) if ((*pp)->id == id) { Timer *d = *pp; *pp = d->next; free(d); break; }
    pthread_mutex_unlock(&tm_lock); return JS_UNDEFINED;
}
static void *timer_thread(void *arg) {
    for (;;) {
        pthread_mutex_lock(&tm_lock);
        while (!g_timers) pthread_cond_wait(&tm_cond, &tm_lock);
        double now = now_ms(), due = g_timers->due;
        if (due > now) {
            struct timespec ts; double abs_ms; clock_gettime(CLOCK_REALTIME, &ts); abs_ms = ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6 + (due - now);
            ts.tv_sec = (time_t)(abs_ms / 1000.0); ts.tv_nsec = (long)((abs_ms - ts.tv_sec * 1000.0) * 1e6);
            pthread_cond_timedwait(&tm_cond, &tm_lock, &ts);
            pthread_mutex_unlock(&tm_lock); continue;
        }
        Timer *t = g_timers; g_timers = t->next; int id = t->id;
        if (t->repeat) { t->due = now + t->ms; tm_insert(t); } else free(t);
        pthread_mutex_unlock(&tm_lock);
        lock_js();
        JSValue a = JS_NewInt32(ctx, id); JSValue r = JS_Call(ctx, g_timer_fn, JS_UNDEFINED, 1, &a); JS_FreeValue(ctx, a);
        if (JS_IsException(r)) dump_exc(ctx);
        JS_FreeValue(ctx, r);
        run_jobs(); unlock_js();
    }
    return NULL;
}

// ------------------------------------------------------------------ Hook-Einsprung (aus kitmod.c, Game-Thread)
int km_js_ready(void) { return g_ready; }
int km_js_enter(int idx, void *regs, uint64_t token) {
    if (!g_ready) return 0;
    lock_js();
    JSValue a[3] = { JS_NewInt32(ctx, idx), JS_NewInt64(ctx, (int64_t)(uintptr_t)regs), JS_NewInt64(ctx, (int64_t)token) };
    JSValue r = JS_Call(ctx, g_enter_fn, JS_UNDEFINED, 3, a);
    int need = 0;
    if (JS_IsException(r)) dump_exc(ctx); else need = JS_ToBool(ctx, r) > 0;
    JS_FreeValue(ctx, r); for (int i = 0; i < 3; i++) JS_FreeValue(ctx, a[i]);
    run_jobs(); unlock_js();
    return need;
}
void km_js_leave(int idx, void *regs, uint64_t token) {
    if (!g_ready) return;
    lock_js();
    JSValue a[3] = { JS_NewInt32(ctx, idx), JS_NewInt64(ctx, (int64_t)(uintptr_t)regs), JS_NewInt64(ctx, (int64_t)token) };
    JSValue r = JS_Call(ctx, g_leave_fn, JS_UNDEFINED, 3, a);
    if (JS_IsException(r)) dump_exc(ctx);
    JS_FreeValue(ctx, r); for (int i = 0; i < 3; i++) JS_FreeValue(ctx, a[i]);
    run_jobs(); unlock_js();
}

// ------------------------------------------------------------------ Initialisierung
static const JSCFunctionListEntry np_funcs[] = {
    JS_CFUNC_MAGIC_DEF("add", 1, np_op, OP_ADD), JS_CFUNC_MAGIC_DEF("sub", 1, np_op, OP_SUB), JS_CFUNC_MAGIC_DEF("and", 1, np_op, OP_AND),
    JS_CFUNC_MAGIC_DEF("or", 1, np_op, OP_OR), JS_CFUNC_MAGIC_DEF("xor", 1, np_op, OP_XOR), JS_CFUNC_MAGIC_DEF("shl", 1, np_op, OP_SHL),
    JS_CFUNC_MAGIC_DEF("shr", 1, np_op, OP_SHR), JS_CFUNC_DEF("not", 0, np_not), JS_CFUNC_DEF("isNull", 0, np_isnull),
    JS_CFUNC_DEF("equals", 1, np_equals), JS_CFUNC_DEF("compare", 1, np_compare), JS_CFUNC_DEF("toString", 1, np_tostring),
    JS_CFUNC_DEF("toInt32", 0, np_toint32), JS_CFUNC_DEF("toUInt32", 0, np_touint32), JS_CFUNC_DEF("toNumber", 0, np_tonumber),
    JS_CFUNC_MAGIC_DEF("readS8", 0, np_read, T_S8), JS_CFUNC_MAGIC_DEF("readU8", 0, np_read, T_U8),
    JS_CFUNC_MAGIC_DEF("readS16", 0, np_read, T_S16), JS_CFUNC_MAGIC_DEF("readU16", 0, np_read, T_U16),
    JS_CFUNC_MAGIC_DEF("readS32", 0, np_read, T_S32), JS_CFUNC_MAGIC_DEF("readU32", 0, np_read, T_U32),
    JS_CFUNC_MAGIC_DEF("readS64", 0, np_read, T_S64), JS_CFUNC_MAGIC_DEF("readU64", 0, np_read, T_U64),
    JS_CFUNC_MAGIC_DEF("readInt", 0, np_read, T_S32), JS_CFUNC_MAGIC_DEF("readUInt", 0, np_read, T_U32),
    JS_CFUNC_MAGIC_DEF("readShort", 0, np_read, T_S16), JS_CFUNC_MAGIC_DEF("readUShort", 0, np_read, T_U16),
    JS_CFUNC_MAGIC_DEF("readLong", 0, np_read, T_S64), JS_CFUNC_MAGIC_DEF("readULong", 0, np_read, T_U64),
    JS_CFUNC_MAGIC_DEF("readPointer", 0, np_read, T_PTR), JS_CFUNC_MAGIC_DEF("readFloat", 0, np_read, T_F32), JS_CFUNC_MAGIC_DEF("readDouble", 0, np_read, T_F64),
    JS_CFUNC_MAGIC_DEF("writeS8", 1, np_write, T_S8), JS_CFUNC_MAGIC_DEF("writeU8", 1, np_write, T_U8),
    JS_CFUNC_MAGIC_DEF("writeS16", 1, np_write, T_S16), JS_CFUNC_MAGIC_DEF("writeU16", 1, np_write, T_U16),
    JS_CFUNC_MAGIC_DEF("writeS32", 1, np_write, T_S32), JS_CFUNC_MAGIC_DEF("writeU32", 1, np_write, T_U32),
    JS_CFUNC_MAGIC_DEF("writeS64", 1, np_write, T_S64), JS_CFUNC_MAGIC_DEF("writeU64", 1, np_write, T_U64),
    JS_CFUNC_MAGIC_DEF("writeInt", 1, np_write, T_S32), JS_CFUNC_MAGIC_DEF("writeUInt", 1, np_write, T_U32),
    JS_CFUNC_MAGIC_DEF("writeShort", 1, np_write, T_S16), JS_CFUNC_MAGIC_DEF("writeUShort", 1, np_write, T_U16),
    JS_CFUNC_MAGIC_DEF("writeLong", 1, np_write, T_S64), JS_CFUNC_MAGIC_DEF("writeULong", 1, np_write, T_U64),
    JS_CFUNC_MAGIC_DEF("writePointer", 1, np_write, T_PTR), JS_CFUNC_MAGIC_DEF("writeFloat", 1, np_write, T_F32), JS_CFUNC_MAGIC_DEF("writeDouble", 1, np_write, T_F64),
    JS_CFUNC_DEF("readUtf8String", 1, np_read_utf8), JS_CFUNC_DEF("readCString", 1, np_read_utf8), JS_CFUNC_DEF("readByteArray", 1, np_read_bytes),
    JS_CFUNC_DEF("writeUtf8String", 1, np_write_utf8), JS_CFUNC_DEF("writeByteArray", 1, np_write_bytes),
};

static int init_runtime(const char *prelude, size_t plen, const char *script, size_t slen) {
    pthread_mutexattr_t ma; pthread_mutexattr_init(&ma); pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_RECURSIVE); pthread_mutex_init(&g_lock, &ma);
    rt = JS_NewRuntime(); if (!rt) return -1;
    JS_SetMaxStackSize(rt, 0);       // Stack-Pruefung aus: Hooks laufen auf wechselnden Threads
    ctx = JS_NewContext(rt); if (!ctx) return -1;
    JS_NewClassID(rt, &np_class); JS_NewClass(rt, np_class, &np_def);
    JS_NewClassID(rt, &sig_class); JS_NewClass(rt, sig_class, &sig_def);
    np_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, np_proto, np_funcs, sizeof np_funcs / sizeof np_funcs[0]);
    JS_SetClassProto(ctx, np_class, JS_DupValue(ctx, np_proto));
    JSValue G = JS_GetGlobalObject(ctx);
    JSValue ptrf = JS_NewCFunction2(ctx, js_ptr, "ptr", 1, JS_CFUNC_generic, 0);
    JS_SetPropertyStr(ctx, ptrf, "prototype", JS_DupValue(ctx, np_proto));
    JS_SetPropertyStr(ctx, np_proto, "constructor", JS_DupValue(ctx, ptrf));
    JS_SetPropertyStr(ctx, G, "NativePointer", JS_DupValue(ctx, ptrf));
    JS_SetPropertyStr(ctx, G, "ptr", ptrf);
    JSValue N = JS_NewObject(ctx);
#define NAT(name, n, fn) JS_SetPropertyStr(ctx, N, name, JS_NewCFunction(ctx, fn, name, n))
    NAT("alloc", 1, n_alloc); NAT("allocUtf8", 1, n_alloc_utf8); NAT("copy", 3, n_copy); NAT("range", 1, n_range); NAT("dlsym", 1, n_dlsym);
    NAT("readFile", 1, n_readfile); NAT("log", 1, n_log); NAT("base", 0, n_base); NAT("hookIndex", 1, n_hookindex);
    NAT("regGet", 2, n_regget); NAT("regSet", 3, n_regset); NAT("nfn", 3, n_nfn); NAT("ncb", 3, n_ncb);
    NAT("tmSet", 3, n_tmset); NAT("tmClear", 1, n_tmclear);
    JS_SetPropertyStr(ctx, G, "__n", N);
    JS_FreeValue(ctx, G);
    JSValue r = JS_Eval(ctx, prelude, plen, "prelude.js", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(r)) { dump_exc(ctx); return -2; } JS_FreeValue(ctx, r);
    G = JS_GetGlobalObject(ctx);
    g_enter_fn = JS_GetPropertyStr(ctx, G, "__km_enter"); g_leave_fn = JS_GetPropertyStr(ctx, G, "__km_leave"); g_timer_fn = JS_GetPropertyStr(ctx, G, "__km_timer");
    JS_FreeValue(ctx, G);
    pthread_t th; pthread_create(&th, NULL, timer_thread, NULL); pthread_detach(th);
    g_ready = 1;
    km_log("Laufzeit bereit, starte Skript");
    lock_js();
    r = JS_Eval(ctx, script, slen, "script.js", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(r)) dump_exc(ctx); else km_log("Skript-Hauptteil ausgefuehrt");
    JS_FreeValue(ctx, r); run_jobs(); unlock_js();
    return 0;
}

typedef struct { const char *prelude, *script; size_t plen, slen; int delay_ms; } StartArgs;
static void *start_thread(void *p) {
    StartArgs *a = p;
    if (a->delay_ms > 0) usleep(a->delay_ms * 1000);
    int rc = init_runtime(a->prelude, a->plen, a->script, a->slen);
    if (rc) { char b[64]; snprintf(b, sizeof b, "Init fehlgeschlagen (%d)", rc); km_log(b); }
    return NULL;
}
void km_runtime_start(uint64_t base, const uint32_t *rvas, int nrvas, const char *prelude, size_t plen, const char *script, size_t slen, int delay_ms) {
    log_open(); install_fault_handlers();
    g_base = base; g_rvas = rvas; g_nrvas = nrvas;
    static StartArgs a; a.prelude = prelude; a.plen = plen; a.script = script; a.slen = slen; a.delay_ms = delay_ms;
    pthread_attr_t at; pthread_attr_init(&at); pthread_attr_setstacksize(&at, 8u << 20);   // grosser Stack fuer den Haupt-Eval
    pthread_t th; pthread_create(&th, &at, start_thread, &a); pthread_detach(th);
}
// fuer Tests (Linux): synchron starten
int km_runtime_start_sync(uint64_t base, const uint32_t *rvas, int nrvas, const char *prelude, size_t plen, const char *script, size_t slen) {
    install_fault_handlers(); g_base = base; g_rvas = rvas; g_nrvas = nrvas;
    return init_runtime(prelude, plen, script, slen);
}
