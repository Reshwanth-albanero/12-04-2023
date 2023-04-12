package com.example.demo.Helper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.cglib.core.internal.Function;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
@Component
public class JwtUtil {
    private static final long serialUID = -2550185165626007488L;
    private static final long JWT_TOKEN_VALID = 5 * 60 * 60;
    private String secret = "Raju123";
    public String getUsernameFromToken(String token){
        return getClaimFromToken(token,Claims::getSubject);
    }
    public Date getExpirationDateFromToken(String token){
        return getClaimFromToken(token,Claims::getExpiration);
    }
    public <T, Claims> T getClaimFromToken(String token, Function<Claims,T> claimsResolver){
        final Claims claims = (Claims) getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }
    protected Claims getAllClaimsFromToken(String token){
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }
    private boolean isTokenExpired(String token){
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public String generateToken(UserDetails userDetails){
        Map<String , Object> Claims = new HashMap<>();
        return doGenerateToken(Claims,userDetails.getUsername());
    }

    private String doGenerateToken(Map<String,Object> Claims,String subject){
        return Jwts.builder().setClaims(Claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALID)).signWith(SignatureAlgorithm.HS512,secret).compact();
    }
    public Boolean validateToken(String token,UserDetails userDetails){
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername())&& !isTokenExpired(token));
    }

}
