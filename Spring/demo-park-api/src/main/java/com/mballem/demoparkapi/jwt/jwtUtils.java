package com.mballem.demoparkapi.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@Slf4j
public class jwtUtils {

    public static final String JWT_BEARER = "Bearer ";

    public static final String JWT_AUTHORIZATION = "Authorization";

    public static final String SECRET_KEY = "0123456789-0123456789-0123456789";

    public static final long EXPIRE_DAYS = 0;

    public static final long EXPIRE_HOURS = 0;

    public static final long EXPIRE_MINUTES = 30;

    private jwtUtils(){
    }

    private static Key generateKey(){
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    //Método gera a data em que o token irá expirar.
    private static Date toExpireDate(Date start) {
        LocalDateTime dateTime = start.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        LocalDateTime end = dateTime.plusDays(EXPIRE_DAYS).plusHours(EXPIRE_HOURS).plusMinutes(EXPIRE_MINUTES);
        return Date.from(end.atZone(ZoneId.systemDefault()).toInstant());
    }

    //Método que gera o token.
    public static jwtToken createToken(String username, String role){
        Date issuedAt = new Date();
        Date limit = toExpireDate(issuedAt);

        String token = Jwts.builder()// Esse método permite as demais configurações
                .setHeaderParam("type", "JWT")
                .setSubject(username)
                .setIssuedAt(issuedAt)//data de criação
                .setExpiration(limit)//data limite do token
                .signWith(generateKey(), SignatureAlgorithm.HS256)//assinatura do token
                .claim("role", role)
                .compact();
        return new jwtToken(token);
    }

    //Método para recuperar o conteúdo do token.
    private static Claims getClaimsFromToken(String token){
        try{
            return Jwts.parserBuilder()
                    .setSigningKey(generateKey()).build()
                    .parseClaimsJws(refactorToken(token)).getBody();
        } catch (JwtException ex){
            log.error(String.format("Token invalido %s", ex.getMessage()));
        }
        return null;
    }

    public static String getUsernameFromToken(String token){
        return getClaimsFromToken(token).getSubject();
    }

    //testa a validade do token.
    public static boolean isTokenValid(String token){
        try{
            Jwts.parserBuilder()
                    .setSigningKey(generateKey()).build()
                    .parseClaimsJws(refactorToken(token));
            return true;
        } catch (JwtException ex){
            log.error(String.format("Token invalido %s", ex.getMessage()));
        }
        return false;
    }

    private static String refactorToken(String token){
        if(token.contains(JWT_BEARER)){
            return token.substring(JWT_BEARER.length());
        }
        return token;
    }

}
