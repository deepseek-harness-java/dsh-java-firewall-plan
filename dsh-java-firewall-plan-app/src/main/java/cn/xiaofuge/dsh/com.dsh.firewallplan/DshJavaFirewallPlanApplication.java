package cn.xiaofuge.dsh.com.dsh.firewallplan;

import cn.xiaofuge.dsh.com.dsh.firewallplan.config.FirewallPlanProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(FirewallPlanProperties.class)
public class DshJavaFirewallPlanApplication {

    public static void main(String[] args) {
        SpringApplication.run(DshJavaFirewallPlanApplication.class, args);
    }
}
