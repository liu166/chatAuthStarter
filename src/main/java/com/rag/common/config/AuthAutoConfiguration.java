package com.rag.common.config;

import com.rag.common.filter.JwtAuthFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;

@AutoConfiguration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthAutoConfiguration {


    @Bean
    public JwtAuthFilter jwtAuthFilter(
            RedisTemplate<String, Object> redisTemplate,
            AuthProperties authProperties) {
        return new JwtAuthFilter(redisTemplate, authProperties);
    }
}