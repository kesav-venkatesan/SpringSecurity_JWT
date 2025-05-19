package com.Security.SpringSecurity.JWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.logging.Logger;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    private static final Logger logger = Logger.getLogger(AuthTokenFilter.class.getName());
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {


        logger.fine("AuthTokenFilter called in URL :{}" + request.getRequestURI());
        try{
            String jwt=parseJwt(request);
            if(jwt!=null && jwtUtils.validateJWTToken(jwt)){
                String username = jwtUtils.getUserNameFromToken(jwt);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities()
                        );
                //setting request details to authentication like IP address
                authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));

                //Adding Security Context
                SecurityContextHolder.getContext().setAuthentication(authentication);

                logger.fine("User Role:{}"+userDetails.getAuthorities());

            }
        }
        catch(Exception e){
            logger.severe("Can't add Authentication context {}"+e.getMessage());
        }
        // Sayins sping to i am dont with my custom filter and move to new filters
        filterChain.doFilter(request, response);

    }

    private String parseJwt(HttpServletRequest request) {
        logger.fine("parseJwt called in URL :{}" + request.getRequestURI());
        return jwtUtils.getJWTFromHeader(request);
    }
}
