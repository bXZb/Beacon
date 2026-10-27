#include "ReflectiveLoader.h"
#if defined(__clang__)
/* LLVM 线: clang 的不可达代码消除把 .5k include 的 int3 墙折叠到 1280B,
 * 而客户端拼接体 2897B 会越界覆盖墙后的真实函数 (crypto_rng/security 等)。
 * 改用 volatile nop 墙 (wall_llvm.h, 3200x1B, volatile asm 不可删除、可达必发射)。 */
#define RefLoadSize 0
#else
#define RefLoadSize 5
#endif

/* extern "C"：本函数是加载器 stub 经名字/序号定位的唯一导出入口，必须以未修饰
   的 C 符号导出。C++ 编译单元下缺省会被名字修饰，GetProcAddress 按原名查找会失败。
   x86 WINAPI 仍会 stdcall 修饰成 _ReflectiveLoader@4，再 fort 一个无修饰别名。 */
#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:ReflectiveLoader=_ReflectiveLoader@4")
#endif
extern "C" DLLEXPORT UINT_PTR WINAPI ReflectiveLoader(LPVOID lpParameter) {

#if defined(__clang__)
#include "wall_llvm.h"
#elif defined(RefLoadSize)
	#if RefLoadSize == 5
		#include "ReflectiveLoader.5k"
	#elif RefLoadSize == 50
		#include "ReflectiveLoader.50k.boom"
	#elif RefLoadSize == 100
		#include "ReflectiveLoader.100k"
	#elif RefLoadSize == 1000
		#include "ReflectiveLoader.1000k.boom"
	#else
		#include "ReflectiveLoader.unknown.size.boom"
	#endif
#else
	#include "ReflectiveLoader.5k"
#endif

	return 0;
}