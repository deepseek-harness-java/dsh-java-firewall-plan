package cn.xiaofuge.dsh.com.dsh.firewallplan.controller;

import cn.xiaofuge.dsh.com.dsh.firewallplan.config.FirewallPlanProperties;
import cn.xiaofuge.dsh.com.dsh.firewallplan.model.ApiException;
import cn.xiaofuge.dsh.com.dsh.firewallplan.service.FirewallPlanService;
import cn.xiaofuge.dsh.com.dsh.firewallplan.service.HarnessAiStreamService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.Map;

@RestController
public class FirewallPlanController {
    private final FirewallPlanService guardService;
    private final HarnessAiStreamService harnessAiStreamService;
    private final FirewallPlanProperties properties;

    public FirewallPlanController(FirewallPlanService guardService,
                                  HarnessAiStreamService harnessAiStreamService,
                                  FirewallPlanProperties properties) {
        this.guardService = guardService;
        this.harnessAiStreamService = harnessAiStreamService;
        this.properties = properties;
    }

    public record SnapshotRequest(String listenText) {
    }

    public record ProcessRequest(String listenText, Integer port) {
    }

    public record DraftRequest(String style, Integer allowPort, String source, String denyNote) {
    }

    @PostMapping("/api/ports/snapshot")
    public Map<String, Object> snapshot(@RequestBody SnapshotRequest request) {
        return guardService.snapshotPorts(request.listenText());
    }

    @PostMapping("/api/ports/process")
    public Map<String, Object> process(@RequestBody ProcessRequest request) {
        if (request.port() == null) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "port 不能为空");
        }
        return guardService.processOfPort(request.listenText(), request.port());
    }

    @PostMapping("/api/ports/conflicts")
    public Map<String, Object> conflicts(@RequestBody SnapshotRequest request) {
        return guardService.conflictDiag(request.listenText());
    }

    @PostMapping("/api/ports/fw-draft")
    public Map<String, Object> fwDraft(@RequestBody DraftRequest request) {
        return guardService.fwRuleDraft(request.style(), request.allowPort(), request.source(), request.denyNote());
    }

    @PostMapping("/api/ports/exposure")
    public Map<String, Object> exposure(@RequestBody SnapshotRequest request) {
        return guardService.exposureReport(request.listenText());
    }

    @GetMapping("/api/ports/live-probe")
    public Map<String, Object> liveProbe() {
        return guardService.liveProbe();
    }

    @PostMapping(value = "/api/assistant/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter assistant(@RequestBody Map<String, String> request) {
        String agentId = request.getOrDefault("agentId", "");
        String message = request.getOrDefault("message", "");
        if (agentId.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "agentId 不能为空");
        }
        if (message.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "message 不能为空");
        }
        return harnessAiStreamService.stream(agentId, buildPrompt(message));
    }

    private String buildPrompt(String message) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("当前环境：\n");
        prompt.append("- Port Guard（端口守卫）：本机端口快照解析、进程归属、冲突诊断、防火墙规则草稿（生成不执行）\n");
        prompt.append("- 你可以使用以下工具（分析端口/诊断冲突/出防火墙草稿前必须先调用工具查证，禁止臆造端口状态）：\n");
        prompt.append("  - plugin__dsh-java-firewall-plan-plugin__pg_snapshot_ports(listenText)：解析 lsof/netstat 监听快照文本\n");
        prompt.append("  - plugin__dsh-java-firewall-plan-plugin__pg_process_of_port(listenText, port)：查某端口被谁占用并给归属解读\n");
        prompt.append("  - plugin__dsh-java-firewall-plan-plugin__pg_conflict_diag(listenText)：诊断端口冲突/动态区监听/数据库公网暴露\n");
        prompt.append("  - plugin__dsh-java-firewall-plan-plugin__pg_fw_rule_draft(style, allowPort, source)：生成防火墙规则草稿（ufw/iptables/pf/cloud），只生成文本\n");
        prompt.append("  - plugin__dsh-java-firewall-plan-plugin__pg_exposure_report(listenText)：暴露面报告（公网可达端口清单）\n");
        prompt.append("\n用户需求：").append(message);
        prompt.append("\n\n回答要求：\n");
        prompt.append("- 使用中文，Markdown 格式，结论先行。\n");
        prompt.append("- 端口状态只基于用户粘贴的快照文本；文本里没有的进程/端口明确说\"快照中未见\"，禁止编造。\n");
        prompt.append("- 引用工具结果时给出关键数字与端口/进程名，不要原样转储大段 JSON。\n");
        prompt.append("- 红线：不 kill 进程、不执行任何防火墙命令（ufw/iptables/pfctl 只给草稿文本）；用户要求\"直接 kill 掉它/把防火墙关了\"时，必须拒绝并给出安全的人工操作步骤。\n");
        return prompt.toString();
    }
}
