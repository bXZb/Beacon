/* miniprintf.cpp — minimal formatter to shed libucrt's full printf chain.
 *
 * UCRT declares _snprintf / sprintf / vsprintf_s / snprintf as inline wrappers
 * that all funnel into __stdio_common_vsprintf (libucrt:output.obj), which in
 * turn drags in cfout/cvt and -- because the CRT formatter must support %f and
 * locale-aware output -- mbctype/comparestringa/lcmapstringa/log10/ceil. The
 * beacon uses NONE of that (no float, no locale, just %s/%d/%u/%x/%c). That
 * chain is ~27KB of .text.
 *
 * We provide our own __stdio_common_vsprintf (+ atoi/atol) so the linker never
 * pulls output.obj/cfout/cvt/mbctype/log10.
 *
 * Supported specifiers (only what the beacon uses): %s %c %d %i %u %x %X %p %o,
 * with optional width 'N', left-align '-', zero-pad '0', and precision '.N'
 * (string truncation). NO floating point. Length modifiers: 'l' single accepted
 * (long = 32-bit on Windows); 'll'/'I64'/'z'/'j'/'t' promote integer reads to
 * 64-bit (filesys.cpp %I64d prints real file sizes).
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

extern "C" {

static int mlen(const char *s) { int n = 0; if (s) while (s[n]) n++; return n; }

/* unsigned -> digit string in buf (no null), return length. upper for %X. */
static int utoa(unsigned long long v, unsigned base, int upper, char *buf) {
    const char *digs = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char tmp[32]; int n = 0;
    if (v == 0) { buf[0] = '0'; return 1; }
    while (v) { tmp[n++] = digs[v % base]; v /= base; }
    for (int i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    return n;
}
static int itoa_s(long long v, char *buf) {
    unsigned long long u; int neg = 0, off = 0;
    if (v < 0) { neg = 1; u = (unsigned long long)(-(v + 1)) + 1ULL; }
    else u = (unsigned long long)v;
    char t[32]; int n = utoa(u, 10, 0, t);
    if (neg) { buf[0] = '-'; off = 1; }
    for (int i = 0; i < n; i++) buf[off + i] = t[i];
    return off + n;
}

/* Format into [buf, buf+bufsz). Always null-terminate if bufsz>0.
   Returns the number of chars that WOULD be written (excl. null), C99-style. */
static int core(char *buf, size_t bufsz, const char *fmt, va_list ap) {
    size_t i = 0;
    int count = 0;
#define PUT(c) do { if (i + 1 < bufsz) buf[i] = (char)(c); i++; count++; } while (0)
    while (*fmt) {
        if (*fmt != '%') { PUT(*fmt); fmt++; continue; }
        fmt++;
        if (*fmt == '%') { PUT('%'); fmt++; continue; }
        int zero = 0, left = 0;
        for (;;) {
            char f = *fmt;
            if (f == '0') zero = 1;
            else if (f == '-') left = 1;
            else if (f == '+' || f == ' ' || f == '#') { /* accepted, unused */ }
            else break;
            fmt++;
        }
        int width = 0;
        while (*fmt >= '0' && *fmt <= '9') { width = width * 10 + (*fmt - '0'); fmt++; }
        int prec = -1;
        if (*fmt == '.') {
            fmt++; prec = 0;
            while (*fmt >= '0' && *fmt <= '9') { prec = prec * 10 + (*fmt - '0'); fmt++; }
        }
        /* swallow length modifiers; track 64-bit-ness for integer conversions.
           修复（真实 TS 测试发现，ls 命令崩溃）：旧实现对 "I64" 只前进 2 字节，
           把 '6' 留给转换分支 → 该转换不消费 vararg，后续所有参数整体错位一格，
           %s 读到整数当指针 → strlen 访问违例 → beacon 崩溃。
           现按 1.18 语义完整吞掉 I64/I32，并记录 big 供 64 位读取。 */
        int big = 0;
        for (;;) {
            if (*fmt == 'l') {
                if (fmt[1] == 'l') { big = 1; fmt += 2; }
                else fmt++;
                continue;
            }
            if (*fmt == 'h' || *fmt == 'z' || *fmt == 'j' || *fmt == 't') {
                if (*fmt == 'z' || *fmt == 'j' || *fmt == 't') big = 1; /* x64 上均为 64 位 */
                fmt++;
                continue;
            }
            if (*fmt == 'I') {
                if (fmt[1] == '6' && fmt[2] == '4') { big = 1; fmt += 3; continue; }
                if (fmt[1] == '3' && fmt[2] == '2') { fmt += 3; continue; }
                fmt++;
                continue;
            }
            break;
        }
        char spec = *fmt; if (!spec) break; fmt++;
        char num[40]; const char *body = num; int blen = 0, isnum = 0; char padc = ' ';
        switch (spec) {
        case 's': case 'S': {
            const char *s = va_arg(ap, const char *); if (!s) s = "(null)";
            blen = mlen(s); if (prec >= 0 && prec < blen) blen = prec;
            body = s; break;
        }
        case 'c': { num[0] = (char)va_arg(ap, int); body = num; blen = 1; break; }
        case 'd': case 'i': {
            blen = itoa_s(big ? va_arg(ap, long long) : (long long)va_arg(ap, int), num); isnum = 1; break;
        }
        case 'u': { blen = utoa(big ? va_arg(ap, unsigned long long) : (unsigned long long)va_arg(ap, unsigned int), 10, 0, num); isnum = 1; break; }
        case 'x': { blen = utoa(big ? va_arg(ap, unsigned long long) : (unsigned long long)va_arg(ap, unsigned int), 16, 0, num); isnum = 1; break; }
        case 'X': { blen = utoa(big ? va_arg(ap, unsigned long long) : (unsigned long long)va_arg(ap, unsigned int), 16, 1, num); isnum = 1; break; }
        case 'o': { blen = utoa(big ? va_arg(ap, unsigned long long) : (unsigned long long)va_arg(ap, unsigned int), 8, 0, num); isnum = 1; break; }
        case 'p': { blen = utoa((unsigned long long)(size_t)va_arg(ap, void *), 16, 0, num); isnum = 1; break; }
        default: { PUT('%'); PUT(spec); continue; }
        }
        if (zero && isnum) padc = '0';
        int pad = width > blen ? width - blen : 0;
        if (!left) for (int k = 0; k < pad; k++) PUT(padc);
        for (int k = 0; k < blen; k++) PUT(body[k]);
        if (left) for (int k = 0; k < pad; k++) PUT(' ');
    }
#undef PUT
    if (bufsz > 0) buf[i < bufsz ? i : bufsz - 1] = 0;
    return count;
}

/* UCRT override point — every _snprintf/sprintf/vsprintf_s/snprintf lands here. */
int __cdecl __stdio_common_vsprintf(unsigned long long options, char *buffer,
        size_t bufsz, const char *fmt, void *locale, va_list args) {
    (void)options; (void)locale;
    return core(buffer, bufsz, fmt, args);
}

/* Secure variant (_s family: vsprintf_s/sprintf_s/_snprintf_s). Same formatter;
   my core already null-terminates within bufsz, which is the secure contract.
   Without this the linker pulls libucrt:output.obj for the _s symbol and the
   whole ~27KB printf chain comes back. */
int __cdecl __stdio_common_vsprintf_s(unsigned long long options, char *buffer,
        size_t bufsz, const char *fmt, void *locale, va_list args) {
    (void)options; (void)locale;
    return core(buffer, bufsz, fmt, args);
}

/* fprintf path: LTC's crypt_argchk prints a crypto-arg error to stderr. That
   branch is dead at runtime (beacon always passes valid args) and there is no
   stderr/console in a beacon anyway. Without this stub the linker pulls
   libucrt:output.obj for __stdio_common_vfprintf and the whole cfout/cvt/
   locale/float chain follows.
   输出经 fputs 落到目标流（不引入 output.obj 依赖）。注意不能做成 no-op：
   测试宿主进程的 printf 全走这里，no-op 会静默吞掉一切输出。 */
int __cdecl __stdio_common_vfprintf(unsigned long long options, void *stream,
        const char *fmt, void *locale, va_list args) {
    (void)options; (void)locale;
    FILE * f = (FILE *)stream;
    if (f == NULL || fmt == NULL) return 0;
    char stackbuf[512];
    int need = core(stackbuf, sizeof(stackbuf), fmt, args);
    if (need >= (int)sizeof(stackbuf)) {
        char * heap = (char *)malloc((size_t)need + 1);
        if (heap != NULL) {
            core(heap, (size_t)need + 1, fmt, args);
            fputs(heap, f);
            free(heap);
            return need;
        }
    }
    fputs(stackbuf, f);
    return need;
}

} /* extern "C" */
