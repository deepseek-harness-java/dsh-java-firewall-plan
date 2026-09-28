# dsh-java-firewall-plan — Port Guard（端口守卫）

> DSH Java Native Plugin 独立 AI 产品 #23/30。AI 驱动的端口守卫：解析 lsof/netstat 监听快照，诊断端口冲突与公网暴露，生成防火墙规则**草稿**。**红线：不 kill 进程、不改防火墙（草稿只生成文本，绝不执行）。**

## 产品定位

"8080 起不来""Redis 怎么暴露在公网了""防火墙该开哪个口"——端口问题高频且高危。Port Guard 把用户粘贴的 `lsof -P -i -n | grep LISTEN` / `netstat -an | grep LISTEN` 快照变成结构化视图：谁在监听、是否公网可达、有无冲突，AI 负责解读与给草稿，但**绝代执行 kill/防火墙命令**。

- App：Spring Boot，端口 `8114`
- Plugin：`dsh-java-firewall-plan-plugin`（Java Native，SPI 注册）

## 工具集（5 个）

| 工具 | 说明 |
|---|---|
| `pg_snapshot_ports` | 解析监听快照文本 → 结构化条目（进程/PID/地址/端口/公网可达/常见服务提示）；兼容真实 lsof 8 列与精简 6 列格式 |
| `pg_process_of_port` | 端口归属：谁占用、是否公网、常见用途、空端口的现场复核建议 |
| `pg_conflict_diag` | 冲突诊断：多进程抢同一端口、动态端口区（>32768）监听、数据库端口公网暴露 |
| `pg_fw_rule_draft` | 防火墙规则草稿：ufw / iptables / pf / cloud 安全组四种风格，含执行顺序提醒（先放 SSH 再 enable）；**只生成文本** |
| `pg_exposure_report` | 暴露面报告：公网可达端口分级（高危=DB/中间件、中=动态区、提示=业务口）+ 处置动作 |

## 安全红线（systemPrompt + PRE_TOOL_USE hook 双保险）

1. 只解析快照文本 + 本机只读 lsof 探测；不 kill 进程、不重启服务、不改防火墙。
2. 防火墙草稿永远只是文本，必须提醒由运维评审后人工执行。
3. 用户要求"直接 kill / 关防火墙"时，AI 必须拒绝并给人工安全步骤。

## REST API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/ports/snapshot` | 快照解析 |
| POST | `/api/ports/process` | 端口归属（listenText + port） |
| POST | `/api/ports/conflicts` | 冲突诊断 |
| POST | `/api/ports/fw-draft` | 防火墙草稿（style/allowPort/source） |
| POST | `/api/ports/exposure` | 暴露面报告 |
| GET | `/api/ports/live-probe` | 本机 lsof 只读探测（失败优雅降级） |
| POST | `/api/assistant/stream` | SSE 对话（转发 harness） |

## E2E

`port_guard_e2e.py` — **32 断言全通过**：

- T0 本机探测优雅降级
- T1 快照解析（数量/公网数/常见服务/回环绑定）
- T2 端口归属（mysqld 占 3306 / MySQL 提示 / 改绑建议 / 空端口复核）
- T3 冲突诊断（端口争用 / 动态区监听 / DB 公网暴露）
- T4 四种防火墙草稿风格 + 红线提醒 + 非法风格 400
- T5 暴露面报告（3306 高危 / 汇总文案）
- T6 SSE AI 经插件工具解析快照（未 shell 绕行）
- T7 SSE AI **拒绝 kill -9 与关防火墙**，给人工安全步骤
- T8 SSE AI 暴露面报告（点名 3306）

## 开发中的修复

- lsof 正则首版漏算 NODE 列（真实输出 8 前导列）→ 改为 `(?:\s+\S+){0,3}` 可变列吸收，同时兼容精简样例 6 列。

## 运行

```bash
mvn package -DskipTests
java -jar dsh-java-firewall-plan-app/target/dsh-java-firewall-plan-app-0.1.0-SNAPSHOT.jar --server.port=8114
# 插件安装/激活同其他产品（pluginId: dsh-java-firewall-plan-plugin）
```

打开 `http://127.0.0.1:8114`，左侧 AI 对话，右侧工作台：快照 / 归属 / 冲突 / 暴露面。
