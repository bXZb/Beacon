/* Win32-only empty BOF: no imports, no beacon API. Passes boff.cpp's
 * ftable-reloc admission so the masked window will take it. CI compiles
 * this to a COFF object; the live test feeds it to binline_execute. */
void go(char * args, int len)
{
	(void)args;
	(void)len;
}
