/* Plan 4.2 (4.10): a host that failed is held until every host has failed.
 * "Updated beacon random and round-robin rotation modes to hold hosts that
 * have failed until all hosts have failed to stabilize connections."
 *
 * Two places pick a host and both get the same rules: strategy.cpp (the DNS
 * beacons) and the hostcfg overlay (every HTTP beacon, from its first cycle).
 * strategy.cpp keeps its state for the whole process, so each strategy gets
 * one continuous sequence here; the overlay re-seeds with hostcfg_init(). */
#include "test_harness.h"
#include <Windows.h>
#include <string.h>
#include "beacon.h"
#include "hostcfg.h"
#include "strategy.h"

/* hostcfg.cpp calls the console callback; the test build has no commands.cpp */
void command_shell_callback(char * buffer, int length, int type) { (void)buffer; (void)length; (void)type; }

/* strategy.cpp has no header for these: it declares them where it defines them */
char * next_host_round_robin(char * hosts, BOOL lastCheckinFailed);
char * next_host_random(char * hosts, BOOL lastCheckinFailed);

/* ---------------------------------------------------------- strategy.cpp */

TEST(rotation_round_robin_holds_a_failed_host) {
	char hosts[] = "a.example,/a,b.example,/b,c.example,/c";

	/* cycle 1: the first host. The flag of the very first call describes no
	 * host (none was used yet), so it must hold nothing: the walk below
	 * comes back to a. */
	CHECK(strcmp(next_host_round_robin(hosts, TRUE), "a.example") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, TRUE), "/a") == 0);
	/* cycle 2: the next one; it fails */
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "b.example") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "/b") == 0);
	/* cycle 3: b failed and is held: c comes next */
	CHECK(strcmp(next_host_round_robin(hosts, TRUE), "c.example") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, TRUE), "/c") == 0);
	/* cycle 4: c answered: the walk wraps to a */
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "a.example") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "/a") == 0);
	/* cycle 5: a answered: c again, b is still held */
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "c.example") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "/c") == 0);
	/* cycle 6: c failed too: every host has now failed, so all are released
	 * and the walk starts over at a */
	CHECK(strcmp(next_host_round_robin(hosts, TRUE), "a.example") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "/a") == 0);
	/* cycle 7: a failed: b is back in the rotation */
	CHECK(strcmp(next_host_round_robin(hosts, TRUE), "b.example") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "/b") == 0);
	/* cycle 8: b failed: c; then c failed: all released again */
	CHECK(strcmp(next_host_round_robin(hosts, TRUE), "c.example") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "/c") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, TRUE), "a.example") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "/a") == 0);
}

TEST(rotation_round_robin_holds_nothing_after_a_good_cycle) {
	/* continues the sequence above: the walk is at b (a just answered) */
	char hosts[] = "a.example,/a,b.example,/b,c.example,/c";
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "b.example") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "/b") == 0);
	/* a good cycle on b changes nothing: on to c, then a again */
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "c.example") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "/c") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "a.example") == 0);
	CHECK(strcmp(next_host_round_robin(hosts, FALSE), "/a") == 0);
}

TEST(rotation_random_never_returns_a_held_host) {
	char hosts[] = "r1.example,/1,r2.example,/2";
	const char * first;
	const char * other;
	const char * uri_of_first;
	const char * uri_of_other;

	/* the first pick is either host, and its call pair returns its own uri */
	first = next_host_random(hosts, TRUE);   /* no host was used before this call: holds nothing */
	if (strcmp(first, "r1.example") == 0) {
		other = "r2.example"; uri_of_first = "/1"; uri_of_other = "/2";
	}
	else {
		CHECK(strcmp(first, "r2.example") == 0);
		other = "r1.example"; uri_of_first = "/2"; uri_of_other = "/1";
	}
	CHECK(strcmp(next_host_random(hosts, TRUE), uri_of_first) == 0);

	/* it failed: held. With two hosts the other one is the only choice,
	 * however many times the beacon asks */
	CHECK(strcmp(next_host_random(hosts, TRUE), other) == 0);
	CHECK(strcmp(next_host_random(hosts, TRUE), uri_of_other) == 0);
	{
		int i;
		for (i = 0; i < 50; i++) {
			CHECK(strcmp(next_host_random(hosts, FALSE), other) == 0);
			CHECK(strcmp(next_host_random(hosts, FALSE), uri_of_other) == 0);
		}
	}

	/* the other one failed too: all held, so all are released and both are
	 * candidates again - each one comes up in 200 picks */
	CHECK(strcmp(next_host_random(hosts, TRUE), first) == 0 || strcmp(next_host_random(hosts, TRUE), other) == 0);
	next_host_random(hosts, FALSE);
	{
		int seen_first = 0, seen_other = 0, i;
		for (i = 0; i < 200; i++) {
			const char * h = next_host_random(hosts, FALSE);
			CHECK(strcmp(h, first) == 0 || strcmp(h, other) == 0);
			seen_first += strcmp(h, first) == 0;
			seen_other += strcmp(h, other) == 0;
			next_host_random(hosts, FALSE);
		}
		CHECK(seen_first > 0 && seen_other > 0);
	}
}

TEST(rotation_dispatch_forwards_the_flag_to_round_robin) {
	/* next_host() routes by strategy. Round-robin (the default) continues
	 * the sequence above: the walk is at b. The flag says a failed, and it
	 * must reach the hold table through the dispatcher. */
	strategy_info si;
	char hosts[] = "a.example,/a,b.example,/b,c.example,/c";
	strategy_setup(&si, HOST_STRATEGY_ROUND_ROBIN, -1, -1, -1);
	CHECK(strcmp(next_host(hosts, TRUE, &si), "b.example") == 0);
	CHECK(strcmp(next_host(hosts, TRUE, &si), "/b") == 0);
	CHECK(strcmp(next_host(hosts, FALSE, &si), "c.example") == 0);
	CHECK(strcmp(next_host(hosts, FALSE, &si), "/c") == 0);
	/* a is held: c -> b */
	CHECK(strcmp(next_host(hosts, FALSE, &si), "b.example") == 0);
	CHECK(strcmp(next_host(hosts, FALSE, &si), "/b") == 0);
}

TEST(rotation_dispatch_keeps_the_failover_strategies_their_own) {
	/* the failover-* and rotate-* strategies (HOST_STRATEGY_EVENT) keep their
	 * own host-moving logic: a failure rotates to the next host, and the
	 * dispatcher's round-robin and random tables are not touched */
	strategy_info si;
	char hosts[] = "f1.example,/1,f2.example,/2,f3.example,/3";
	strategy_setup(&si, HOST_STRATEGY_EVENT, -1, -1, 0);   /* rotate off, failover on every failure */
	CHECK(strcmp(next_host(hosts, FALSE, &si), "f1.example") == 0);
	CHECK(strcmp(next_host(hosts, FALSE, &si), "/1") == 0);
	CHECK(strcmp(next_host(hosts, TRUE, &si), "f2.example") == 0);
	CHECK(strcmp(next_host(hosts, TRUE, &si), "/2") == 0);
}

TEST(rotation_dispatch_routes_random) {
	/* the random table is bound to r1/r2 (above); the other two are bound
	 * to other names, so a pick from r1/r2 can only come from the random path */
	strategy_info si;
	char hosts[] = "r1.example,/1,r2.example,/2";
	strategy_setup(&si, HOST_STRATEGY_RANDOM, -1, -1, -1);
	{
		const char * h = next_host(hosts, FALSE, &si);
		CHECK(strcmp(h, "r1.example") == 0 || strcmp(h, "r2.example") == 0);
	}
}

/* --------------------------------------------------------- hostcfg.cpp */

/* setting[67] = SETTING_DOMAIN_STRATEGY, TYPE_SHORT; the blob format is
 * test_settings.cpp's (XOR 0x2E over the whole patch area). strategy < 0:
 * the payload has no strategy setting. */
extern char myargs[];
static void bake_strategy(int strategy) {
	unsigned char blob[4096];
	int i;
	memset(blob, 0, sizeof(blob));
	if (strategy >= 0) {
		blob[1] = 67;                    /* index */
		blob[3] = 1;                     /* TYPE_SHORT */
		blob[5] = 2;                     /* length */
		blob[6] = (unsigned char)(strategy >> 8);
		blob[7] = (unsigned char)(strategy & 0xff);
	}
	for (i = 0; i < 4096; i++)
		blob[i] ^= 0x2E;
	memcpy(myargs, blob, sizeof(blob));
	settings_init(NULL);
	CHECK(setting_short(SETTING_DOMAIN_STRATEGY) == (strategy < 0 ? 0 : strategy));
}

/* one pick of the overlay */
static const char * overlay_pick(void) {
	static char host[128], uri[256];
	if (!hostcfg_pick(host, 128, uri, 256))
		return "";
	return host;
}

static std::string collected;
static void collect(char * buffer, int length, int type) { (void)type; collected.append(buffer, buffer + length); }

/* a beacon_config host packet: the verb, then the length-prefixed strings
 * (big-endian ints, as the client writes them) */
static std::string host_packet(int verb, const char * a, const char * b) {
	std::string p;
	unsigned int words[3];
	int n = 0, i;
	words[n++] = (unsigned int)verb;
	words[n++] = a ? (unsigned int)strlen(a) : 0;
	words[n++] = b ? (unsigned int)strlen(b) : 0;
	for (i = 0; i < n; i++) {
		p += (char)((words[i] >> 24) & 0xff);
		p += (char)((words[i] >> 16) & 0xff);
		p += (char)((words[i] >> 8) & 0xff);
		p += (char)(words[i] & 0xff);
		if (i == 1 && a)
			p += a;
		if (i == 2 && b)
			p += b;
	}
	return p;
}

/* the info line of one host */
static std::string info_line(const char * host) {
	std::string packet = host_packet(0, NULL, NULL);
	size_t at;
	collected.clear();
	command_host_config(&packet[0], (int)packet.size(), collect);
	at = collected.find(std::string(host) + " ");
	CHECK(at != std::string::npos);
	return collected.substr(at, collected.find('\n', at) - at);
}

TEST(overlay_round_robin_holds_a_failed_host) {
	bake_strategy(HOST_STRATEGY_ROUND_ROBIN);
	hostcfg_init("a.example,/a,b.example,/b,c.example,/c");

	CHECK(strcmp(overlay_pick(), "a.example") == 0);
	hostcfg_note("a.example", TRUE);
	/* b fails: held from now on */
	CHECK(strcmp(overlay_pick(), "b.example") == 0);
	hostcfg_note("b.example", FALSE);
	/* c, then the walk wraps to a, then c again */
	CHECK(strcmp(overlay_pick(), "c.example") == 0);
	hostcfg_note("c.example", TRUE);
	CHECK(strcmp(overlay_pick(), "a.example") == 0);
	hostcfg_note("a.example", TRUE);
	CHECK(strcmp(overlay_pick(), "c.example") == 0);
	hostcfg_note("c.example", TRUE);
	CHECK(strcmp(overlay_pick(), "a.example") == 0);
	hostcfg_note("a.example", TRUE);
	CHECK(strcmp(overlay_pick(), "c.example") == 0);
	/* the operator sees it: host info lists b as held, the others as ok */
	CHECK(info_line("b.example").find("HELD") != std::string::npos);
	CHECK(info_line("b.example").find("fails=1") != std::string::npos);
	CHECK(info_line("a.example").find(" ok  ") != std::string::npos);
	CHECK(info_line("c.example").find(" ok  ") != std::string::npos);
	/* and lets it back in by hand */
	{
		std::string packet = host_packet(5, "b.example", NULL);
		command_host_config(&packet[0], (int)packet.size(), collect);
	}
	CHECK(info_line("b.example").find(" ok  ") != std::string::npos);
	CHECK(strcmp(overlay_pick(), "b.example") == 0);
}

TEST(overlay_operator_hold_takes_a_working_host_out) {
	bake_strategy(HOST_STRATEGY_ROUND_ROBIN);
	hostcfg_init("a.example,/a,b.example,/b,c.example,/c");
	{
		std::string packet = host_packet(4, "b.example", NULL);
		command_host_config(&packet[0], (int)packet.size(), collect);
	}
	CHECK(info_line("b.example").find("HELD") != std::string::npos);
	CHECK(strcmp(overlay_pick(), "a.example") == 0);
	CHECK(strcmp(overlay_pick(), "c.example") == 0);
	CHECK(strcmp(overlay_pick(), "a.example") == 0);
}

TEST(overlay_releases_every_host_once_all_are_held) {
	bake_strategy(HOST_STRATEGY_ROUND_ROBIN);
	hostcfg_init("a.example,/a,b.example,/b");

	CHECK(strcmp(overlay_pick(), "a.example") == 0);
	hostcfg_note("a.example", FALSE);
	CHECK(strcmp(overlay_pick(), "b.example") == 0);
	hostcfg_note("b.example", FALSE);
	/* both failed: released, the walk starts over */
	CHECK(strcmp(overlay_pick(), "a.example") == 0);
	CHECK(strcmp(overlay_pick(), "b.example") == 0);
}

TEST(overlay_operator_hold_and_a_failure_release_everything) {
	/* "All held hosts are automatically released when all hosts have been
	 * held": one held by hand, the other by a failure */
	bake_strategy(HOST_STRATEGY_ROUND_ROBIN);
	hostcfg_init("a.example,/a,b.example,/b");
	{
		std::string packet = host_packet(4, "a.example", NULL);
		command_host_config(&packet[0], (int)packet.size(), collect);
	}
	CHECK(strcmp(overlay_pick(), "b.example") == 0);
	hostcfg_note("b.example", FALSE);
	CHECK(info_line("a.example").find("HELD") != std::string::npos);
	CHECK(info_line("b.example").find("HELD") != std::string::npos);
	/* the next pick finds all of them held and releases them */
	CHECK(strcmp(overlay_pick(), "a.example") == 0);
	CHECK(info_line("a.example").find(" ok  ") != std::string::npos);
	CHECK(info_line("b.example").find(" ok  ") != std::string::npos);
}

TEST(overlay_single_host_keeps_retrying) {
	bake_strategy(HOST_STRATEGY_ROUND_ROBIN);
	hostcfg_init("only.example,/only");

	CHECK(strcmp(overlay_pick(), "only.example") == 0);
	hostcfg_note("only.example", FALSE);
	/* held, and since it is the only host released at once */
	CHECK(strcmp(overlay_pick(), "only.example") == 0);
	hostcfg_note("only.example", FALSE);
	CHECK(strcmp(overlay_pick(), "only.example") == 0);
	CHECK(info_line("only.example").find("fails=2") != std::string::npos);
}

TEST(overlay_payload_without_strategy_setting_holds_too) {
	/* no strategy baked: read as 0 = round-robin, so a failed host is held */
	bake_strategy(-1);
	hostcfg_init("a.example,/a,b.example,/b,c.example,/c");
	CHECK(strcmp(overlay_pick(), "a.example") == 0);
	hostcfg_note("a.example", FALSE);
	CHECK(strcmp(overlay_pick(), "b.example") == 0);
	hostcfg_note("b.example", TRUE);
	CHECK(strcmp(overlay_pick(), "c.example") == 0);
	hostcfg_note("c.example", TRUE);
	/* a is held: the walk goes c -> b */
	CHECK(strcmp(overlay_pick(), "b.example") == 0);
	CHECK(strcmp(overlay_pick(), "c.example") == 0);
}

TEST(overlay_failover_strategies_hold_nothing) {
	bake_strategy(HOST_STRATEGY_EVENT);
	hostcfg_init("a.example,/a,b.example,/b");

	CHECK(strcmp(overlay_pick(), "a.example") == 0);
	hostcfg_note("a.example", FALSE);
	CHECK(strcmp(overlay_pick(), "b.example") == 0);
	hostcfg_note("b.example", TRUE);
	/* a was not held: the walk comes back to it */
	CHECK(strcmp(overlay_pick(), "a.example") == 0);
	hostcfg_note("a.example", FALSE);
	CHECK(strcmp(overlay_pick(), "b.example") == 0);
	/* the failure is still counted */
	CHECK(info_line("a.example").find("fails=2") != std::string::npos);
	CHECK(info_line("a.example").find(" ok  ") != std::string::npos);
}

TEST(overlay_random_strategy_skips_the_held_hosts) {
	int i, seen_a = 0, seen_b = 0, seen_c = 0;
	bake_strategy(HOST_STRATEGY_RANDOM);
	hostcfg_init("a.example,/a,b.example,/b,c.example,/c");

	/* nothing held: every host comes up in 64 picks */
	for (i = 0; i < 64; i++) {
		const char * h = overlay_pick();
		seen_a += strcmp(h, "a.example") == 0;
		seen_b += strcmp(h, "b.example") == 0;
		seen_c += strcmp(h, "c.example") == 0;
	}
	CHECK(seen_a > 0 && seen_b > 0 && seen_c > 0);

	/* a and b failed: only c is left, pick after pick */
	hostcfg_note("a.example", FALSE);
	hostcfg_note("b.example", FALSE);
	for (i = 0; i < 64; i++)
		CHECK(strcmp(overlay_pick(), "c.example") == 0);

	/* c failed too: all held, all released */
	hostcfg_note("c.example", FALSE);
	seen_a = seen_b = seen_c = 0;
	for (i = 0; i < 64; i++) {
		const char * h = overlay_pick();
		seen_a += strcmp(h, "a.example") == 0;
		seen_b += strcmp(h, "b.example") == 0;
		seen_c += strcmp(h, "c.example") == 0;
	}
	CHECK(seen_a > 0 && seen_b > 0 && seen_c > 0);
}

TEST(overlay_pick_fills_the_hosts_own_uri) {
	char host[128], uri[256];
	bake_strategy(HOST_STRATEGY_ROUND_ROBIN);
	hostcfg_init("a.example,/a,b.example,/b");
	CHECK(hostcfg_pick(host, 128, uri, 256) == TRUE);
	CHECK(strcmp(host, "a.example") == 0 && strcmp(uri, "/a") == 0);
	CHECK(hostcfg_pick(host, 128, uri, 256) == TRUE);
	CHECK(strcmp(host, "b.example") == 0 && strcmp(uri, "/b") == 0);
}
