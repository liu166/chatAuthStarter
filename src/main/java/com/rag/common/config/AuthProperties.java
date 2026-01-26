package com.rag.common.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {
    private String jwtSecret = "auth-secret-auth-secret-auth-secret-1234";
    private int expireHours = 2;
    private List<String> excludes = new ArrayList<>();
}