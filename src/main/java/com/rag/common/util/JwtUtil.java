package com.rag.common.util;

import com.rag.common.config.AuthProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

public class JwtUtil {


    private final AuthProperties authProperties;
    private Key key;
    private long expireMs;


    public JwtUtil(AuthProperties authProperties) {
        this.authProperties = authProperties;
    }


    @PostConstruct
    public void init() {
        String secret = authProperties.getJwtSecret();
        if (secret == null || secret.length() < 32) {
            throw new IllegalArgumentException(
                    "auth.jwt-secret 长度必须 >= 32"
            );
        }
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
        this.expireMs = authProperties.getExpireHours() * 3600_000L;
    }


    public String createToken(String sessionId) {
        return Jwts.builder()
                .claim("sessionId", sessionId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expireMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }


    public Claims parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}