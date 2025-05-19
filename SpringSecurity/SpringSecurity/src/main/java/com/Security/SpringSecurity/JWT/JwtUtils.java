package com.Security.SpringSecurity.JWT;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.logging.Logger;

@Component
public class JwtUtils {
    public static  Logger logger = Logger.getLogger(JwtUtils.class.getName());
    private static long expireTimeInMills=300000;
    private String JwtSecret="MySecretCodeisThishawmoiyqwhftrbgmcerubgmcxorwnmxoiwyhxqrwuo";
    public String getJWTFromHeader(HttpServletRequest request){
        String token =request.getHeader("Authorization");
        if(token != null && token.startsWith("Bearer ")){
            return token.substring(7);
        }
        return null;
    }
 
    public String generateJWTToken(UserDetails userDetails) {
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime()+expireTimeInMills))
                .signWith(key())
                .compact();
    }

    public String getUserNameFromToken(String token){
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build().parseSignedClaims(token)
                .getPayload().getSubject();
    }
    public Key key(){
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(JwtSecret)
        );
    }

    public boolean validateJWTToken(String token){
        try{
           logger.fine("Validating JWT token");
            Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseClaimsJws(token);
            return  true;
        }
        catch(Exception e){
           logger.severe( String.format("Invalid JWT token: %s", e.getMessage()));
            return false;
        }
    }
}
