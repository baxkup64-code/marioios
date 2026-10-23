// Linux-Selbsttest der Laufzeit (x86_64/arm64): gcc ... test_main.c km_runtime.c quickjs*.c && ./a.out prelude.js test.js
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "km_runtime.h"
static char *slurp(const char *p, size_t *n) { FILE *f = fopen(p, "rb"); if (!f) { perror(p); exit(2); } fseek(f, 0, SEEK_END); *n = ftell(f); fseek(f, 0, SEEK_SET); char *b = malloc(*n + 1); fread(b, 1, *n, f); b[*n] = 0; fclose(f); return b; }
static unsigned char fakeimg[1 << 16];
static const uint32_t rvas[] = { 0x100, 0x200 };
int main(int argc, char **argv) {
    size_t pn, sn; char *pre = slurp(argv[1], &pn), *scr = slurp(argv[2], &sn);
    int rc = km_runtime_start_sync((uint64_t)(uintptr_t)fakeimg, rvas, 2, pre, pn, scr, sn);
    usleep(argc > 3 ? atoi(argv[3]) * 1000 : 600 * 1000);   // Timer abwarten
    return rc;
}
