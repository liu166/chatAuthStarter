package com.rag.common.config;

import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Getter
@Component
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    /**
     * 不需要鉴权的接口前缀
     * 默认值：/auth/login
     * 可从 application.yml 多行列表覆盖
     */
    private List<String> excludes = new ArrayList<>();

    public void setExcludes(List<String> excludes) {
        if (excludes != null) {
            this.excludes = excludes;
        }
    }


}