package com.Security.SpringSecurity.Controller;

import com.Security.SpringSecurity.JWT.JwtUtils;
import com.Security.SpringSecurity.JWT.LoginRequest;
import com.Security.SpringSecurity.JWT.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class Controller {
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private AuthenticationManager authenticationManager;
    @GetMapping("api")
    public String api() {
        return "Hello World";
    }
    @PreAuthorize("hasRole('USER')")
    @GetMapping("user")
    public String apiUsers() {
        return "Hello All";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("admin")
    public String apiAdmin() {
        return "Hello Admin";
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );
        } catch (Exception e) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", e.getMessage());
            map.put("status", false);
            return new ResponseEntity<>(map, HttpStatus.UNAUTHORIZED);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token =jwtUtils.generateJWTToken(userDetails);
        List<String> roles=userDetails.getAuthorities().stream()
                .map(item->item.getAuthority()).toList();
        LoginResponse loginResponse = new LoginResponse(userDetails.getUsername(),token, roles);
        return new ResponseEntity<>(loginResponse, HttpStatus.OK);
    }
}
