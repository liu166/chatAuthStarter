package com.rag.common.constant;

public interface AuthConstants {

    /** HTTP Header */
    String AUTH_HEADER = "Authorization";
    String TOKEN_PREFIX = "Bearer ";


    /** Redis Key 前缀 */
    String REDIS_SESSION_PREFIX = "auth:session:";
}
