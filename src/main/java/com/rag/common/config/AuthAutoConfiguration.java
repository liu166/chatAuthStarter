package com.rag.common.config;

import com.rag.common.filter.JwtAuthFilter;
import com.rag.common.util.JwtUtil;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;

@AutoConfiguration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthAutoConfiguration {


    @Bean
    public JwtAuthFilter jwtAuthFilter(
            RedisTemplate<String, Object> redisTemplate,
            AuthProperties authProperties,
            JwtUtil jwtUtil) { // 注入 JwtUtil
        return new JwtAuthFilter(redisTemplate, authProperties, jwtUtil);
    }


    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        return template;
    }


    @Bean
    public JwtUtil jwtUtil(AuthProperties authProperties) {
        return new JwtUtil(authProperties); // 生成 JwtUtil Bean
    }
}