package com.yugi.cauth.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    // 認証が必要なプライベートリソース
    @GetMapping("/private/resource")
    public String privateResource(@AuthenticationPrincipal Jwt jwt) {
        System.out.println("/private/resource");
        // JWTの詳細やユーザー情報を使用してレスポンスを生成
        return "Private resource accessed with JWT: " + jwt.getTokenValue();
    }

    // 認証が不要なパブリックリソース
    @GetMapping("/public/resource")
    public String publicResource() {
        return "Public resource accessed without authentication.";
    }
}