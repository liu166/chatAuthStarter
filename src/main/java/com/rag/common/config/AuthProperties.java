package com.rag.common.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Data
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {


    /**
     * 不需要鉴权的接口前缀
     * 例如：/auth/login, /public
     */
    private List<String> excludes = List.of("/auth/login");
}