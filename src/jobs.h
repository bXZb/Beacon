#define JOB_ENTRY_PROCESS   0
#define JOB_ENTRY_NAMEDPIPE 1

#define JOB_STATUS_GOOD 0
#define JOB_STATUS_DEAD 1

#define JOB_DESCRIPTION_LENGTH 64

typedef struct _PSH_ENTRY {
	DWORD jid; /* job ID */
	PROCESS_INFORMATION pi;
	HANDLE read_stdout;
	HANDLE write_stdout;
	void * next;
	short tag;
	short status;
	DWORD pid;
	DWORD type;				/* callback type */
	short mode;				/* our mode... stream or blob */
	char description[JOB_DESCRIPTION_LENGTH];
} psh_entry;

/* track a process as a job */
void psh_track(PROCESS_INFORMATION pi, HANDLE read_stdout, HANDLE write_stdout);
psh_entry * process_track(PROCESS_INFORMATION pi, HANDLE read_stdout, HANDLE write_stdout, char * desc);

/* track a named pipe as a job */
void pipe_track(HANDLE read_stdout, DWORD pid, DWORD type, char * desc, short mode);

/* interal functions */
void job_add(psh_entry * entry);
int read_all_from_pipe(HANDLE handle, char * buffer, int maxlength);
int read_blob_from_pipe(HANDLE handle, char * buffer, int maxlength);

/* functions defined elsewhere */
int read_all(HANDLE pipe, char * buffer, int max);
void pipe_try(HANDLE handle, DWORD wait);
BOOL connect_pipe(char* pipename, HANDLE* pipe);