package com.yugi.cauth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login(Model model) {
        //TODO デバックコメント
        System.out.println("LoginController");
        // ログインページのビューを返します（ログイン処理はSpring Securityが担当）
        // ここにホームページに表示するデータを追加できる
        model.addAttribute("message", "Welcome to the Home Page!");
        return "login"; // login.htmlをレンダリングします
    }
}
