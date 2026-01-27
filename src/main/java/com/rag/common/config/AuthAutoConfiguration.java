package com.rag.common.config;

import com.rag.common.filter.JwtAuthFilter;
import com.rag.common.util.JwtUtil;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@AutoConfiguration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthAutoConfiguration {


    @Bean
    @ConditionalOnMissingBean
    public JwtAuthFilter jwtAuthFilter(
            RedisTemplate<String, Object> redisTemplate,
            AuthProperties authProperties,
            JwtUtil jwtUtil) { // 注入 JwtUtil
        return new JwtAuthFilter(redisTemplate, authProperties, jwtUtil);
    }

    @Bean
    @ConditionalOnClass(SecurityFilterChain.class)
    public SecurityFilterChain authSecurityFilterChain(
            HttpSecurity http,
            JwtAuthFilter jwtAuthFilter) throws Exception {


        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
    @Bean
    public JwtUtil jwtUtil(AuthProperties authProperties) {
        return new JwtUtil(authProperties); // 生成 JwtUtil Bean
    }
}