package com.rag.common.config;

import com.rag.common.filter.JwtAuthFilter;
import com.rag.common.util.JwtUtil;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@AutoConfiguration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthAutoConfiguration {

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:5173")
                        .allowedMethods("GET", "POST", "PUT", "DELETE")
                        .allowCredentials(true);
            }
        };
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthFilter jwtAuthFilter(
            @Qualifier("redisTemplate") RedisTemplate<?, ?> redisTemplate,
            AuthProperties authProperties,
            JwtUtil jwtUtil) {
        return new JwtAuthFilter(redisTemplate, authProperties, jwtUtil);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtUtil jwtUtil(AuthProperties authProperties) {
        return new JwtUtil(authProperties);
    }
}