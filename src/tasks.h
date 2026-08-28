/*
 * Common Definitions for Background Tasks (e.g., Keystroke Logger, Token Guard, etc.)
 */

#define KEYLOG_BUFFER 1048576

void klog(char * buffer, HANDLE lock, char * fmt, ...);
