package com.rag.common.filter;

import com.rag.common.config.AuthProperties;
import com.rag.common.constant.AuthConstants;
import com.rag.common.model.LoginUser;
import com.rag.common.util.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
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
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws IOException, ServletException {


        String path = request.getRequestURI();


        List<String> excludes = properties.getExcludes();
        if (excludes != null && !excludes.isEmpty()) {
            if (excludes.stream().anyMatch(path::startsWith)) {
                chain.doFilter(request, response);
                return;
            }
        }

        // ✅ 关键修改1：处理OPTIONS请求
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }


        String header = request.getHeader(AuthConstants.AUTH_HEADER);
        if (header == null || !header.startsWith(AuthConstants.TOKEN_PREFIX)) {
            // ✅ 关键修改2：认证失败也要继续过滤器链
            response.setStatus(401);
            SecurityContextHolder.clearContext(); // 清理安全上下文
            chain.doFilter(request, response); // ⚠️ 必须调用这个方法
            return;
        }


        String token = header.substring(AuthConstants.TOKEN_PREFIX.length());


        // ⚡ 使用注入的 jwtUtil 而不是静态方法
        Claims claims;
        try {
            claims = jwtUtil.parseToken(token);
        } catch (Exception e) {
            // ✅ 关键修改3：异常时也要继续过滤器链
            response.setStatus(401);
            SecurityContextHolder.clearContext();
            chain.doFilter(request, response);
            return;
        }


        String sessionId = claims.get("sessionId", String.class);


        Map<String, Object> session =
                (Map<String, Object>) redisTemplate.opsForValue()
                        .get(AuthConstants.REDIS_SESSION_PREFIX + sessionId);


        if (session == null) {
            // ✅ 关键修改4：Redis中不存在也要继续过滤器链
            response.setStatus(401);
            SecurityContextHolder.clearContext();
            chain.doFilter(request, response);
            return;
        }

        // ✅ 关键修改5：确保这里不会抛出异常
        try {
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
                    new UsernamePasswordAuthenticationToken(
                            loginUser,
                            null,
                            authorities
                    );


            SecurityContextHolder.getContext().setAuthentication(auth);

        } catch (Exception e) {
            // ✅ 关键修改6：创建用户对象时异常也要处理
            response.setStatus(401);
            SecurityContextHolder.clearContext();
        }

        // ✅ 关键修改7：无论如何都要调用 chain.doFilter()
        chain.doFilter(request, response);
    }
}