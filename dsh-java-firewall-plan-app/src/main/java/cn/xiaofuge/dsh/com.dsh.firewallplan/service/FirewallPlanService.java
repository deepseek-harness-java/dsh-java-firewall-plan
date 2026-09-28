package cn.xiaofuge.dsh.com.dsh.firewallplan.service;

import cn.xiaofuge.dsh.com.dsh.firewallplan.config.FirewallPlanProperties;
import cn.xiaofuge.dsh.com.dsh.firewallplan.model.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Port Guard 端口守卫：
 * - 端口占用快照（解析用户粘贴的 lsof/netstat 文本，或本机只读探测）
 * - 进程归属解读
 * - 冲突诊断（多进程抢端口/动态区监听/数据库公网暴露）
 * - 防火墙规则草稿（只生成文本，不执行任何命令）
 * - 暴露面报告（0.0.0.0 监听 vs 127.0.0.1 监听）
 * 红线：不 kill 进程、不改防火墙（pfctl/iptables/ufw 只给草稿）。
 */
@Service
public class FirewallPlanService {

    /** lsof -P -i -n 输出行：兼容真实 8 前导列（COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME）与精简 6 列样例；(?:\s+\S+){0,3} 吸收中间可变列。 */
    private static final Pattern LSOF_LINE = Pattern.compile(
            "^(\\S+)\\s+(\\d+)\\s+(\\S+)\\s+\\S+\\s+\\S+(?:\\s+\\S+){0,3}\\s+(TCP|UDP)\\s+(\\S+)\\s*(\\(LISTEN\\))?.*$");
    /** netstat -an 输出：tcp4 0 0 *.8080 *.* LISTEN */
    private static final Pattern NETSTAT_LINE = Pattern.compile(
            "^(tcp4?|udp4?)\\s+\\d+\\s+\\d+\\s+(\\S+)\\s+\\S+\\s+(LISTEN|\\S*)\\s*$");
    private static final Pattern PORT_IN_ADDR = Pattern.compile("(?:\\.|:)(\\d+)$");

    /** 常见端口 → 用途/风险，用于解读与建议。 */
    private static final Map<Integer, String> WELL_KNOWN = Map.ofEntries(
            Map.entry(22, "SSH（勿对公网开放密码登录）"),
            Map.entry(80, "HTTP"),
            Map.entry(443, "HTTPS"),
            Map.entry(3306, "MySQL（不应直接暴露公网）"),
            Map.entry(5432, "PostgreSQL（不应直接暴露公网）"),
            Map.entry(6379, "Redis（无密码=数据裸奔）"),
            Map.entry(8080, "HTTP 备选/Tomcat"),
            Map.entry(8443, "HTTPS 备选"),
            Map.entry(9090, "管理控制台常见端口"),
            Map.entry(27017, "MongoDB（不应直接暴露公网）"),
            Map.entry(9200, "Elasticsearch（历史上大量勒索案例）"),
            Map.entry(2375, "Docker Remote API（未加 TLS= root 等于送人）"));

    /** 动态/临时端口区下限（Linux 32768，macOS 49152）。 */
    private static final int EPHEMERAL_LOW_LINUX = 32768;

    public FirewallPlanService(FirewallPlanProperties properties) {
    }

    // ---------- 1. 端口快照 ----------

    public Map<String, Object> snapshotPorts(String listenText) {
        List<Map<String, Object>> entries = parseListenText(listenText);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("listenCount", entries.size());
        result.put("publicCount", entries.stream().filter(e -> (Boolean) e.get("public")).count());
        result.put("udpCount", entries.stream().filter(e -> "UDP".equals(e.get("proto"))).count());
        result.put("wellKnownCount", entries.stream().filter(e -> e.get("wellKnown") != null && !String.valueOf(e.get("wellKnown")).isEmpty()).count());
        result.put("entries", entries);
        return result;
    }

    private List<Map<String, Object>> parseListenText(String text) {
        if (text == null || text.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "listenText 不能为空（可粘贴 lsof -P -i -n | grep LISTEN 或 netstat -an | grep LISTEN 输出）");
        }
        List<Map<String, Object>> entries = new ArrayList<>();
        for (String raw : text.split("\\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.toLowerCase().startsWith("command") || line.startsWith("Proto")) continue;
            Map<String, Object> e = parseLsofLine(line);
            if (e == null) e = parseNetstatLine(line);
            if (e != null) entries.add(e);
        }
        return entries;
    }

    private Map<String, Object> parseLsofLine(String line) {
        Matcher m = LSOF_LINE.matcher(line);
        if (!m.find()) return null;
        String addr = m.group(5);
        Matcher pm = PORT_IN_ADDR.matcher(addr);
        if (!pm.find()) return null;
        if (m.group(6) == null) return null; // 只关注 LISTEN
        int port = Integer.parseInt(pm.group(1));
        return buildEntry(m.group(1), Integer.parseInt(m.group(2)), m.group(3), m.group(4), addr, port);
    }

    private Map<String, Object> parseNetstatLine(String line) {
        Matcher m = NETSTAT_LINE.matcher(line);
        if (!m.find()) return null;
        if (!"LISTEN".equals(m.group(3))) return null;
        String addr = m.group(2);
        Matcher pm = PORT_IN_ADDR.matcher(addr);
        if (!pm.find()) return null;
        int port = Integer.parseInt(pm.group(1));
        return buildEntry("(netstat)", 0, "", m.group(1).toLowerCase().startsWith("udp") ? "UDP" : "TCP", addr, port);
    }

    private Map<String, Object> buildEntry(String process, int pid, String user, String proto,
                                           String addr, int port) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("process", process);
        e.put("pid", pid);
        e.put("user", user);
        e.put("proto", proto);
        e.put("addr", addr);
        e.put("port", port);
        boolean wildcard = addr.startsWith("*") || addr.startsWith("0.0.0.0") || addr.startsWith("[::]") || addr.contains("*.");
        e.put("public", wildcard);
        e.put("ephemeral", port >= EPHEMERAL_LOW_LINUX);
        String known = WELL_KNOWN.get(port);
        e.put("wellKnown", known == null ? "" : known);
        return e;
    }

    // ---------- 2. 进程归属 ----------

    public Map<String, Object> processOfPort(String listenText, int port) {
        List<Map<String, Object>> entries = parseListenText(listenText);
        List<Map<String, Object>> hits = entries.stream()
                .filter(e -> (Integer) e.get("port") == port)
                .toList();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("port", port);
        result.put("hitCount", hits.size());
        result.put("holders", hits);
        result.put("wellKnown", WELL_KNOWN.getOrDefault(port, ""));
        if (hits.size() > 1) {
            result.put("conflict", true);
            result.put("advice", "该端口被 " + hits.size() + " 个进程同时声明占用（快照文本层面），实际同时 LISTEN 只可能一个成功，另一个可能在反复重启——用 lsof -i :" + port + " 现场确认");
        } else if (hits.size() == 1) {
            Map<String, Object> h = hits.get(0);
            result.put("conflict", false);
            result.put("advice", (Boolean) h.get("public")
                    ? "监听在 " + h.get("addr") + "（所有网卡可达），若非有意对外，建议改绑 127.0.0.1"
                    : "监听在 " + h.get("addr") + "（仅本机可达），外部访问需经隧道/反代");
        } else {
            result.put("conflict", false);
            result.put("advice", "快照中无人监听 " + port + "：要么服务没起，要么快照过期，现场用 lsof -i :" + port + " 复核");
        }
        return result;
    }

    // ---------- 3. 冲突诊断 ----------

    public Map<String, Object> conflictDiag(String listenText) {
        List<Map<String, Object>> entries = parseListenText(listenText);
        List<Map<String, Object>> issues = new ArrayList<>();
        // 同端口多进程声明
        Map<Integer, List<Map<String, Object>>> byPort = entries.stream()
                .collect(Collectors.groupingBy(e -> (Integer) e.get("port"), LinkedHashMap::new, Collectors.toList()));
        byPort.forEach((port, group) -> {
            if (group.size() > 1) {
                Map<String, Object> issue = new LinkedHashMap<>();
                issue.put("type", "port-contention");
                issue.put("port", port);
                issue.put("processes", group.stream().map(g -> g.get("process") + "(" + g.get("pid") + ")").toList());
                issue.put("advice", "多进程声明同一端口：留一个，其余改端口或停掉");
                issues.add(issue);
            }
        });
        for (Map<String, Object> e : entries) {
            int port = (Integer) e.get("port");
            if ((Boolean) e.get("ephemeral")) {
                Map<String, Object> issue = new LinkedHashMap<>();
                issue.put("type", "ephemeral-listen");
                issue.put("port", port);
                issue.put("process", e.get("process"));
                issue.put("advice", "监听在动态端口区（>" + (EPHEMERAL_LOW_LINUX - 1) + "）：重启后端口可能被别的进程抢走，建议固定端口");
                issues.add(issue);
            }
            String known = WELL_KNOWN.getOrDefault(port, "");
            if ((Boolean) e.get("public") && (port == 3306 || port == 5432 || port == 6379 || port == 27017 || port == 9200 || port == 2375)) {
                Map<String, Object> issue = new LinkedHashMap<>();
                issue.put("type", "db-public");
                issue.put("port", port);
                issue.put("process", e.get("process"));
                issue.put("advice", known + "监听在公网可达地址：立即改绑 127.0.0.1 或加防火墙规则（草稿见 pg_fw_rule_draft）");
                issues.add(issue);
            }
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("listenCount", entries.size());
        result.put("issueCount", issues.size());
        result.put("issues", issues);
        return result;
    }

    // ---------- 4. 防火墙规则草稿 ----------

    public Map<String, Object> fwRuleDraft(String style, Integer allowPort, String source, String denyNote) {
        String s = style == null || style.isBlank() ? "ufw" : style.trim().toLowerCase();
        int port = allowPort == null ? 443 : allowPort;
        String src = source == null || source.isBlank() ? "any" : source.trim();
        List<String> lines = new ArrayList<>();
        List<String> notes = new ArrayList<>();
        switch (s) {
            case "ufw" -> {
                lines.add("# 1) 默认拒绝入站（先放行 SSH 再执行，防止锁死自己）");
                lines.add("ufw default deny incoming");
                lines.add("# 2) 放行 SSH（管理通道必须先通）");
                lines.add("ufw allow 22/tcp");
                lines.add("# 3) 放行业务端口");
                lines.add(src.equals("any") ? "ufw allow " + port + "/tcp" : "ufw allow from " + src + " to any port " + port + " proto tcp");
                lines.add("# 4) 启用");
                lines.add("ufw enable");
                notes.add("执行顺序很重要：先 allow 22 再 enable，否则云主机可能直接失联");
            }
            case "iptables" -> {
                lines.add("# 1) 已建立连接与回环放行（必须在最前）");
                lines.add("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
                lines.add("iptables -A INPUT -i lo -j ACCEPT");
                lines.add("# 2) 放行 SSH");
                lines.add("iptables -A INPUT -p tcp --dport 22 -j ACCEPT");
                lines.add("# 3) 放行业务端口");
                lines.add(src.equals("any") ? "iptables -A INPUT -p tcp --dport " + port + " -j ACCEPT" : "iptables -A INPUT -p tcp -s " + src + " --dport " + port + " -j ACCEPT");
                lines.add("# 4) 其余拒绝");
                lines.add("iptables -A INPUT -p tcp -j DROP");
                notes.add("iptables 规则重启即失效，持久化用 iptables-persistent / netfilter-persistent");
            }
            case "pf" -> {
                lines.add("# /etc/pf.conf 追加（macOS/BSD）");
                lines.add("pass in on lo0 all");
                lines.add("pass in proto tcp from any to any port 22");
                lines.add(src.equals("any") ? "pass in proto tcp from any to any port " + port : "pass in proto tcp from " + src + " to any port " + port);
                lines.add("block in all");
                notes.add("pf 规则按首条匹配生效，pass 必须写在 block 之前；改完 pfctl -f /etc/pf.conf && pfctl -e");
            }
            case "cloud" -> {
                lines.add("# 云安全组等价规则（控制台按此核对）");
                lines.add("INGRESS 22/tcp   FROM <管理网段/堡垒机>");
                lines.add("INGRESS " + port + "/tcp FROM " + (src.equals("any") ? "0.0.0.0/0（确认是否真需要公网）" : src));
                lines.add("DEFAULT egress all ALLOW / ingress 未显式放行即拒绝");
                notes.add("安全组是白名单模型：只加需要的，删掉 0.0.0.0/0 的宽规则");
            }
            default -> {
                throw new ApiException(HttpStatus.BAD_REQUEST, "style 仅支持 ufw / iptables / pf / cloud");
            }
        }
        if (denyNote != null && !denyNote.isBlank()) {
            notes.add("补充说明：" + denyNote.trim());
        }
        notes.add("红线：本工具只生成草稿文本，不会执行任何防火墙命令——由运维评审后人工执行");
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("style", s);
        result.put("allowPort", port);
        result.put("source", src);
        result.put("lineCount", lines.size());
        result.put("lines", lines);
        result.put("notes", notes);
        return result;
    }

    // ---------- 5. 暴露面报告 ----------

    public Map<String, Object> exposureReport(String listenText) {
        List<Map<String, Object>> entries = parseListenText(listenText);
        List<Map<String, Object>> publicList = entries.stream().filter(e -> (Boolean) e.get("public")).toList();
        List<Map<String, Object>> localList = entries.stream().filter(e -> !(Boolean) e.get("public")).toList();
        List<Map<String, Object>> findings = new ArrayList<>();
        for (Map<String, Object> e : publicList) {
            int port = (Integer) e.get("port");
            String known = WELL_KNOWN.getOrDefault(port, "");
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("port", port);
            f.put("process", e.get("process"));
            f.put("addr", e.get("addr"));
            if (!known.isEmpty()) {
                f.put("level", "high");
                f.put("finding", known + " 对所有网卡开放");
                f.put("action", port == 22 ? "保留但强制密钥登录" : "改绑 127.0.0.1 或防火墙限制来源");
            } else if ((Boolean) e.get("ephemeral")) {
                f.put("level", "medium");
                f.put("finding", "动态端口区服务对外可见");
                f.put("action", "固定端口并收进防火墙管理");
            } else {
                f.put("level", "info");
                f.put("finding", "业务端口对外可见");
                f.put("action", "确认是否需要公网直达，不需要就走反代");
            }
            findings.add(f);
        }
        long highCount = findings.stream().filter(f -> "high".equals(f.get("level"))).count();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("totalListen", entries.size());
        result.put("publicCount", publicList.size());
        result.put("localCount", localList.size());
        result.put("highCount", highCount);
        result.put("findings", findings);
        result.put("summary", publicList.isEmpty()
                ? "所有监听都绑在本机回环/内网地址，公网暴露面为 0"
                : publicList.size() + " 个端口对外可达（其中 " + highCount + " 个高危），优先处理数据库与中间件类");
        return result;
    }

    /** 供 E2E / UI 的本机只读探测（lsof 失败即空，优雅降级）。 */
    public Map<String, Object> liveProbe() {
        List<String> lines = new ArrayList<>();
        try {
            Process p = new ProcessBuilder("/usr/sbin/lsof", "-P", "-i", "-n").start();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    if (line.contains("LISTEN")) lines.add(line);
                }
            }
            p.waitFor();
        } catch (Exception ignored) {
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("probeAvailable", !lines.isEmpty());
        result.put("sample", String.join("\n", lines.stream().limit(20).toList()));
        result.put("note", lines.isEmpty() ? "本机 lsof 不可用或无监听，请手动粘贴 lsof/netstat 输出" : "已取到本机监听样本，可直接交给快照工具");
        return result;
    }
}
