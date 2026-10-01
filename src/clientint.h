/* SMB/extc2 channel buffer ceiling. Parenthesized - the unparenthesized
 * form silently misparses in any MAX_GET - x / foo(MAX_GET, y) expression.
 * (The HTTP entry files define their own runtime MAX_GET from
 * SETTING_MAXGET - a different, profile-driven value.) */
#define MAX_GET (1024 * 1024)

/* initialize our client sub-system */
void client_init(LCHANNEL channel);

/* free resources associated with our client sub-system */
void client_stop();

/* flush... */
void client_flush();

/* read/write process loop for tasks */
void client_process();

/* close the client... link client may opt to do something different */
void client_close();