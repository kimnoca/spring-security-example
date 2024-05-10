package com.example.securityexample.user.api;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/jwt")
public class JwtTestController {
    @GetMapping("/test")
    String test() {
        return "test";
    }
}
