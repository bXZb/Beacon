typedef struct {
	char    * fakeargs;
	char    * realargs;
	DWORD     length;
} ARGUMENT_RECORD;

BOOL argue_should_spoof(char * buffer, ARGUMENT_RECORD * record);
BOOL argue_restore(PROCESS_INFORMATION * pi, ARGUMENT_RECORD * record);