# 并发模型与共享状态审计

## 总模型

beacon 是**单主循环 + 按需工作线程**的结构：

- 主循环（`beacon()` / dnsb / extc2 / pivot 各自的循环）驱动 checkin、任务解析、
  下载轮询（`download_poll`）；
- 任务执行路径上的长操作（shell、注入、elevate 监听等）经 `run_thread_start`
  起线程（`thread.cpp`），`SETTING_CFG_CAUTION=1` 时走 `_run_thread_start`
  包装（据设置走不同创建语义）；
- `safe_exit()`（`thread.cpp`）为唯一统一退出路径：先 `track_memory_cleanup()`
  清理全部登记内存，再按 `SETTING_EXIT_FUNK` 选择 ExitThread/ExitProcess/长眠。

## 全局可变状态清单与约定

| 状态 | 文件 | 访问线程 | 约定 |
|---|---|---|---|
| `settings`/`beacon_ptr`/`myargs` | settings.cpp | 主线程 init，全线程只读 | settings_init 幂等守卫在 ReflectiveDll.cpp |
| `download_list`/`read_buffer`/`download_id` | files.cpp | 主循环（download_poll/process_download） | 仅主循环触碰；条目登记 track_memory，正常路径 remove+free，退出路径兜底 |
| `argue_list` | argue.cpp | 任务线程（argue add/remove/list）与注入路径（should_spoof）读 | 条目只在任务执行线程写；主循环注入时读。增删发生在任务回调内（串行），无并发写 |
| `jobs` 链表 | jobs.cpp | 主循环调度 + 任务线程完成回调 | job 完成回调与调度均经主循环通道串行化 |
| `tokens`（token 存储） | tokens.cpp | 任务线程（ steal/use） | 增删在任务回调内串行 |
| `hServerPipe`/`hElevateThread`/`systemToken` | elevate.cpp | pre 写线程句柄，post 等待并关闭 | post 现在保证句柄关闭 + 状态复位（可重入），见 elevate.cpp 注释 |
| `bigsession`/`agentid` | metadata.cpp | init 写一次，checkin 读 | 初始化后只读 |
| webserver（伪 HTTP 服务） | webserver.cpp | 独立监听线程 | 与主循环仅经回调队列交互 |
| `track_memory` 三元组 | track_memory.cpp | 登记：各处；清理：safe_exit（单线程） | `track_memory_remove` 使正常路径释放与退出兜底互斥（防二次释放） |

## 已知边界（审计结论，P2）

1. **上述"串行"均依赖 CS 的任务调度模型**（任务命令在主循环逐条派发、
   完成结果经 callback 回队）。绕开该模型直接跨线程调用命令函数不受保护。
2. `next_host_round_robin` 的 `static token`（strategy.cpp）是主循环独占的
   轮换游标——pivot/dnsb 变体同为主循环调用，成立。
3. 退出竞态：safe_exit 由触发线程执行 track_memory_cleanup；若此时仍有
   工作线程在跑（如未完成的 elevate 等待），其堆访问不受保护。CS 语义上
   exit_funk 场景本就接受这一窗口；如需收紧，应先 join 已知工作线程。
4. 上传/下载缓冲（`read_buffer`）与 `MAX_PACKET` 相关的容量约束见 files.cpp，
   调整包大小时须同步。

## 修改守则

- 新增全局可变状态时：先回答"哪个线程写、哪个线程读、谁保证先后"，
  并登记到上表；
- 需要堆分配且生命周期跨任务的长存对象：登记 `track_memory_add`，
  正常释放前 `track_memory_remove`；短命对象不要登记（造成退出双重释放面）。
