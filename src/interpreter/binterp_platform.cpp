/* ---------------------------------------------------------------------------
 * Beacon Interpreter platform shim (tier-3 item 12).
 *
 * picoc (jpoirier/picoc, BSD) vendored under src/interpreter/ and compiled
 * as C (per-file CompileAsC in beacon.vcxproj - the project default is
 * CompileAsCpp). This translation unit compiles as C++ like the rest of
 * the beacon, so every symbol picoc's C core calls is wrapped in
 * extern "C".
 *
 * Retargets picoc for an in-process beacon: no console, no filesystem,
 * output funneled into the beacon callback. The picoc heap is one
 * HeapInit malloc block, which the interpreter entry registers with
 * track_memory so the sleepmask masks the whole VM state while the beacon
 * sleeps.
 * ------------------------------------------------------------------------- */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>

extern "C" {
#include "picoc.h"
#include "interpreter.h"

/* picoc's platform.h declares this extern; the modern core only uses the
 * Picoc.PicocExitBuf member, but keep the global defined for link safety */
extern jmp_buf PicocExitBuf;
}

jmp_buf PicocExitBuf;

extern void bi_putc_raw(char c);

static FILE bi_fake_stdout; /* identity only: IOFILE is FILE*, we never let
                             * anything dereference it as a real stream */

extern "C" {

/* initialize the I/O system - picoc core calls this from PicocInitialize */
void BasicIOInit(Picoc *pc)
{
    pc->CStdOut = &bi_fake_stdout;
}

void PlatformInit(Picoc *pc)
{
    (void)pc;
}

void PlatformCleanup(Picoc *pc)
{
    (void)pc;
}

/* interactive input never happens (we only PicocParse with RunIt=TRUE) */
char *PlatformGetLine(char *Buf, int MaxLen, const char *Prompt)
{
    (void)Buf; (void)MaxLen; (void)Prompt;
    return NULL;
}

int PlatformGetCharacter()
{
    return -1;
}

/* every character picoc writes lands in our output buffer */
void PlatformPutc(unsigned char OutCh, union OutputStreamInfo *Stream)
{
    (void)Stream;
    bi_putc_raw((char)OutCh);
}

/* no filesystem: includes resolve through registered builtin libraries
 * only (stdlib/string/ctype/math/time/errno/stdbool map to picoc's
 * cstdlib; beacon.h/windows.h/internal.h are registered by the bridge).
 * Anything else is a script error. */
char *PlatformReadFile(Picoc *pc, const char *FileName)
{
    ProgramFailNoParser(pc, "beacon-interpreter: include '%s' is not available "
                            "(supported: beacon.h, windows.h, internal.h, stdlib.h, "
                            "string.h, ctype.h, math.h, time.h, errno.h, stdbool.h)",
                        FileName);
    return NULL;
}

void PlatformExit(Picoc *pc, int RetVal)
{
    pc->PicocExitValue = RetVal;
    longjmp(pc->PicocExitBuf, 1);
}

/* note: PlatformMakeTempName is provided by picoc's own platform.c; the
 * beacon has no temp files to make anyway */

/* the beacon bridge provides the library surface (no library_msvc.c) */
extern void bi_library_init(Picoc *pc);
void PlatformLibraryInit(Picoc *pc)
{
    bi_library_init(pc);
}

} /* extern "C" */
