package com.Security.SpringSecurity.JWT;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class LoginResponse {
    private String username;
    private String JwtToken;
    private List<String> roles;
}
