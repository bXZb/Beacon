#include "ReflectiveLoader.h"
#define RefLoadSize 5

/* extern "C"：本函数是加载器 stub 经名字/序号定位的唯一导出入口，必须以未修饰
   的 C 符号导出。C++ 编译单元下缺省会被名字修饰，GetProcAddress 按原名查找会失败。 */
extern "C" DLLEXPORT UINT_PTR WINAPI ReflectiveLoader(LPVOID lpParameter) {

#if defined(RefLoadSize)
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