package cn.xiaofuge.dsh.com.dsh.firewallplan.plugin;

import cn.xiaofuge.deepseek.harness.domain.model.entity.AbstractTool;
import cn.xiaofuge.deepseek.harness.domain.model.entity.ToolDefinition;
import cn.xiaofuge.deepseek.harness.domain.spi.AbstractHarnessPlugin;
import cn.xiaofuge.deepseek.harness.domain.spi.PluginContext;
import cn.xiaofuge.deepseek.harness.domain.spi.PluginHookResult;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

public class DshFirewallPlanPlugin extends AbstractHarnessPlugin {
    public static final String PLUGIN_ID = "dsh-java-firewall-plan-plugin";

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    public DshFirewallPlanPlugin() {
        super(PLUGIN_ID);
    }

    @Override
    public List<ToolDefinition> tools() {
        return List.of(
                new SnapshotPortsTool(),
                new ProcessOfPortTool(),
                new ConflictDiagTool(),
                new FwRuleDraftTool(),
                new ExposureReportTool()
        );
    }

    @Override
    public void configure(PluginContext context) {
        super.configure(context);
        context.registerSystemPrompt("firewall-plan-firewallplan-capabilities", 20, """
                ## DSH Port Guard Plugin
                - 所有工具只解析用户粘贴的监听快照文本（lsof/netstat 输出），或做本机只读 lsof 探测；不 kill 进程、不改防火墙、不重启服务。
                - pg_fw_rule_draft 只生成防火墙规则草稿文本（ufw/iptables/pf/cloud 安全组），绝不执行；必须提醒用户由运维评审后人工执行。
                - 发现数据库/中间件端口公网暴露时，先说风险再给改绑 127.0.0.1 或防火墙限源的草稿。
                - 用户要求"直接 kill 掉进程/关掉防火墙"时，必须拒绝并解释风险，给人工操作步骤。
                """);
        context.registerHook("PRE_TOOL_USE", (toolName, payloadJson) -> {
            if (toolName != null && toolName.startsWith("plugin__" + PLUGIN_ID + "__pg_")) {
                return PluginHookResult.context("DSH Port Guard audit: read-only analysis, drafts only, no kill/no firewall exec.");
            }
            return null;
        });
    }

    private String post(String path, String json, Map<String, Object> args) {
        String adminUrl = baseUrl(args);
        return send(HttpRequest.newBuilder(URI.create(adminUrl + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build());
    }

    private String baseUrl(Map<String, Object> args) {
        Object override = args == null ? null : args.get("adminBaseUrl");
        return override == null || String.valueOf(override).isBlank()
                ? System.getenv().getOrDefault("DSH_FIREWALL_PLAN_ADMIN_URL", "http://127.0.0.1:8114")
                : String.valueOf(override);
    }

    private String send(HttpRequest request) {
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                return failJson(response.statusCode(), response.body());
            }
            return response.body();
        } catch (Exception e) {
            return failJson(0, e.getMessage());
        }
    }

    private String failJson(int status, String message) {
        return "{\"error\":true,\"status\":" + status + ",\"message\":\"" + json(message) + "\"}";
    }

    private String json(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private String str(Map<String, Object> args, String key) {
        Object value = args == null ? null : args.get(key);
        return value == null ? "" : String.valueOf(value);
    }

    private String textJson(Map<String, Object> args) {
        return "{\"listenText\":\"" + json(str(args, "listenText")) + "\"}";
    }

    private class SnapshotPortsTool extends AbstractTool {
        @Override public String name() { return "pg_snapshot_ports"; }
        @Override public String description() { return "解析端口监听快照文本（lsof -P -i -n | grep LISTEN 或 netstat -an | grep LISTEN 输出），输出结构化监听条目（进程/PID/地址/端口/是否公网可达）。用户粘贴端口快照时调用。"; }
        @Override public Map<String, Object> parameters() {
            return objectSchema()
                    .prop("listenText", stringSchema("lsof 或 netstat 的 LISTEN 行文本"))
                    .prop("adminBaseUrl", stringSchema("可选，Port Guard 后台地址，默认 http://127.0.0.1:8114"))
                    .required("listenText")
                    .build();
        }
        @Override public boolean isConcurrencySafe(Object args) { return true; }
        @Override protected java.util.concurrent.CompletableFuture<cn.xiaofuge.deepseek.harness.domain.model.entity.ToolExecutionResult>
        run(Map<String, Object> args, cn.xiaofuge.deepseek.harness.domain.model.entity.ToolRunContext ctx) {
            return ok(post("/api/ports/snapshot", textJson(args), args));
        }
    }

    private class ProcessOfPortTool extends AbstractTool {
        @Override public String name() { return "pg_process_of_port"; }
        @Override public String description() { return "查某端口被谁占用：返回占用进程、是否公网可达、常见用途与归属解读。用户问\"8080 被谁占了\"时调用。"; }
        @Override public Map<String, Object> parameters() {
            return objectSchema()
                    .prop("listenText", stringSchema("端口监听快照文本"))
                    .prop("port", stringSchema("要查的端口号"))
                    .prop("adminBaseUrl", stringSchema("可选，后台地址"))
                    .required("listenText", "port")
                    .build();
        }
        @Override public boolean isConcurrencySafe(Object args) { return true; }
        @Override protected java.util.concurrent.CompletableFuture<cn.xiaofuge.deepseek.harness.domain.model.entity.ToolExecutionResult>
        run(Map<String, Object> args, cn.xiaofuge.deepseek.harness.domain.model.entity.ToolRunContext ctx) {
            String body = "{\"listenText\":\"" + json(str(args, "listenText")) + "\",\"port\":" + str(args, "port") + "}";
            return ok(post("/api/ports/process", body, args));
        }
    }

    private class ConflictDiagTool extends AbstractTool {
        @Override public String name() { return "pg_conflict_diag"; }
        @Override public String description() { return "端口冲突诊断：多进程声明同一端口、动态端口区监听、数据库端口公网暴露。排查\"端口起不来/时好时坏\"时调用。"; }
        @Override public Map<String, Object> parameters() {
            return objectSchema()
                    .prop("listenText", stringSchema("端口监听快照文本"))
                    .prop("adminBaseUrl", stringSchema("可选，后台地址"))
                    .required("listenText")
                    .build();
        }
        @Override public boolean isConcurrencySafe(Object args) { return true; }
        @Override protected java.util.concurrent.CompletableFuture<cn.xiaofuge.deepseek.harness.domain.model.entity.ToolExecutionResult>
        run(Map<String, Object> args, cn.xiaofuge.deepseek.harness.domain.model.entity.ToolRunContext ctx) {
            return ok(post("/api/ports/conflicts", textJson(args), args));
        }
    }

    private class FwRuleDraftTool extends AbstractTool {
        @Override public String name() { return "pg_fw_rule_draft"; }
        @Override public String description() { return "生成防火墙规则草稿文本（style: ufw/iptables/pf/cloud；allowPort；source 网段）。只生成草稿不执行，含执行顺序提醒。用户要防火墙方案时调用。"; }
        @Override public Map<String, Object> parameters() {
            return objectSchema()
                    .prop("style", stringSchema("ufw / iptables / pf / cloud，默认 ufw"))
                    .prop("allowPort", stringSchema("要放行的业务端口，默认 443"))
                    .prop("source", stringSchema("允许的来源网段，默认 any"))
                    .prop("denyNote", stringSchema("补充说明"))
                    .prop("adminBaseUrl", stringSchema("可选，后台地址"))
                    .build();
        }
        @Override public boolean isConcurrencySafe(Object args) { return true; }
        @Override protected java.util.concurrent.CompletableFuture<cn.xiaofuge.deepseek.harness.domain.model.entity.ToolExecutionResult>
        run(Map<String, Object> args, cn.xiaofuge.deepseek.harness.domain.model.entity.ToolRunContext ctx) {
            String body = "{\"style\":\"" + json(str(args, "style")) + "\",\"allowPort\":" + (str(args, "allowPort").isBlank() ? "null" : str(args, "allowPort"))
                    + ",\"source\":\"" + json(str(args, "source")) + "\",\"denyNote\":\"" + json(str(args, "denyNote")) + "\"}";
            return ok(post("/api/ports/fw-draft", body, args));
        }
    }

    private class ExposureReportTool extends AbstractTool {
        @Override public String name() { return "pg_exposure_report"; }
        @Override public String description() { return "暴露面报告：公网可达（0.0.0.0/*）监听清单 + 分级（高危/中/提示）+ 处置动作。做安全巡检时调用。"; }
        @Override public Map<String, Object> parameters() {
            return objectSchema()
                    .prop("listenText", stringSchema("端口监听快照文本"))
                    .prop("adminBaseUrl", stringSchema("可选，后台地址"))
                    .required("listenText")
                    .build();
        }
        @Override public boolean isConcurrencySafe(Object args) { return true; }
        @Override protected java.util.concurrent.CompletableFuture<cn.xiaofuge.deepseek.harness.domain.model.entity.ToolExecutionResult>
        run(Map<String, Object> args, cn.xiaofuge.deepseek.harness.domain.model.entity.ToolRunContext ctx) {
            return ok(post("/api/ports/exposure", textJson(args), args));
        }
    }
}
