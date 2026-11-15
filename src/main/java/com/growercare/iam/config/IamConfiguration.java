package com.growercare.iam.config;

import com.growercare.outbox.OutboxWriter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import tools.jackson.databind.json.JsonMapper;

@Configuration(proxyBeanMethods = false)
public class IamConfiguration {

    @Bean
    OutboxWriter outboxWriter(JdbcClient jdbc, JsonMapper json) {
        return new OutboxWriter(jdbc, json);
    }
}
