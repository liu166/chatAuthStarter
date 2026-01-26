package com.rag.common.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

public class JwtUtil {


    private static final String SECRET = "auth-secret-auth-secret-auth-secret-1234"; // 够长
    private static final Key KEY = Keys.hmacShaKeyFor(SECRET.getBytes());


    /** 生成 token，只存 sessionId */
    public static String createToken(String sessionId) {
        return Jwts.builder()
                .claim("sessionId", sessionId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 2 * 60 * 60 * 1000)) // 2h
                .signWith(KEY, SignatureAlgorithm.HS256)
                .compact();
    }


    /** 解析 token */
    public static Claims parseToken(String token) {
        Jws<Claims> jws = Jwts.parserBuilder()
                .setSigningKey(KEY)
                .build()
                .parseClaimsJws(token);
        return jws.getBody();
    }
}