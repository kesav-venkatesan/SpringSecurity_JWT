package com.Security.SpringSecurity.JWT;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

//Handle unauthorized request
@Component
public class AuthEntryPointJWT implements AuthenticationEntryPoint {
    private static final Logger logger = Logger.getLogger(AuthEntryPointJWT.class.getName());

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        logger.severe("Authentication Failed");

        //Setting what type response have to send
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        //ResponseStatus
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        //Body of Response
        Map<String, Object> map = new HashMap<>();
        map.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        map.put("message", authException.getMessage());
        map.put("error", "unauthorized");
//        getRequestURI() → /app/api/data
//        getServletPath() → /app
        map.put("path", request.getRequestURI());

        //Making the map object into response body
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), map);
    }
}
