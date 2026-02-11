package com.rag.common.util;

import com.rag.common.model.LoginUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import reactor.core.publisher.Mono;

public class AuthContextHolder {

    /**
     * 获取当前登录用户（同步线程）
     */
    public static LoginUser getLoginUser() {
        Authentication authentication = SecurityContextHolder
                .getContext()
                .getAuthentication();

        if (authentication == null) {
            return null;
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof LoginUser loginUser) {
            return loginUser;
        }

        return null;
    }

    /**
     * 获取当前用户 ID（同步 + Reactor 兼容）
     */
    public static Long getUserId() {

        // 1️⃣ 优先从 SecurityContext（HTTP 请求线程）
        LoginUser user = getLoginUser();
        if (user != null) {
            return user.getUserId();
        }

        // 2️⃣ 再从 Reactor Context（异步 / Flux / Mono）
        try {
            return Mono.deferContextual(ctx -> {
                        if (ctx.hasKey("USER_ID")) {
                            return Mono.just((Long) ctx.get("USER_ID"));
                        }
                        return Mono.empty();
                    })
                    .block();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 获取用户名
     */
    public static String getUsername() {
        LoginUser user = getLoginUser();
        return user != null ? user.getUsername() : null;
    }
}
