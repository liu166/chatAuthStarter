package com.rag.common.filter;

import com.rag.common.config.AuthProperties;
import com.rag.common.constant.AuthConstants;
import com.rag.common.model.LoginUser;
import com.rag.common.util.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class JwtAuthFilter extends OncePerRequestFilter {


    private final RedisTemplate<?, ?> redisTemplate;
    private final AuthProperties properties;
    private final JwtUtil jwtUtil;


    public JwtAuthFilter(RedisTemplate<?, ?> redisTemplate,
                         AuthProperties properties,
                         JwtUtil jwtUtil) {
        this.redisTemplate = redisTemplate;
        this.properties = properties;
        this.jwtUtil = jwtUtil;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String path = request.getRequestURI();
        List<String> excludes = properties.getExcludes();
        if (excludes != null && !excludes.isEmpty()) {
            if (excludes.stream().anyMatch(path::startsWith)) {
                chain.doFilter(request, response);
                return;
            }
        }

        // 放行 OPTIONS
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        try {
            String token = header.substring(7);
            Claims claims = jwtUtil.parseToken(token);

            String sessionId = claims.get("sessionId", String.class);
            Map<String, Object> session =
                    (Map<String, Object>) redisTemplate.opsForValue()
                            .get("auth:session:" + sessionId);

            if (session == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            LoginUser loginUser = new LoginUser(
                    ((Number) session.get("userId")).longValue(),
                    (String) session.get("username"),
                    (List<String>) session.get("roles")
            );

            List<SimpleGrantedAuthority> authorities =
                    loginUser.getRoles().stream()
                            .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                            .toList();

            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(loginUser, null, authorities);

            SecurityContextHolder.getContext().setAuthentication(auth);

            // 👇 关键：把 userId 放进 Reactor Context
            chain.doFilter(new HttpServletRequestWrapper(request) {
                @Override
                public Object getAttribute(String name) {
                    if ("USER_ID".equals(name)) {
                        return loginUser.getUserId();
                    }
                    return super.getAttribute(name);
                }
            }, response);

        } catch (Exception e) {
            e.printStackTrace();
            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

}