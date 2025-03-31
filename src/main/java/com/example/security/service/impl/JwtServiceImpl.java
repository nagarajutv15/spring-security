package com.example.security.service.impl;

import com.example.security.exception.TokenException;
import com.example.security.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.util.WebUtils;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
@CrossOrigin
public class JwtServiceImpl implements JwtService {

    public static String SECRET = null;

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    @Value("${application.security.jwt.cookie-name}")
    private String jwtCookieName;

    @Value("${application.security.jwt.refresh-token.cookie-name}")
    private String refreshTokenCookieName;


    @Override
    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    private <T> T extractClaims(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token).getPayload();
    }

    private SecretKey getSignKey() {
        byte[] keys = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keys);
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        Map<String, Objects> claims = new HashMap<>();
        return generateToken(claims, userDetails);
    }

    private String generateToken(Map<String, Objects> claims, UserDetails userDetails) {
        Date date = new Date(System.currentTimeMillis() + jwtExpiration);
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(date)
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        String userName = extractUsername(token);
        if(isTokenExipred(token)){
            throw new TokenException(token, "JWT Token is Expired");
        }
        return (userName.equals(userDetails.getUsername()) && !isTokenExipred(token));
    }

    private boolean isTokenExipred(String token){
        return extractClaims(token, Claims::getExpiration).before(new Date());
    }

    @Override
    public ResponseCookie generateJwtCookie(String jwt) {
        return ResponseCookie.from(jwtCookieName,jwt)
                .path("/")
                .maxAge(24*60*60)//24 hr
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .build();
    }

    @Override
    public String getJwtFromCookies(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request,jwtCookieName);
        if(cookie != null){
            return cookie.getValue();
        } else{
            return null;
        }
    }

    @Override
    public ResponseCookie getCleanJwtCookie() {
        return ResponseCookie.from(jwtCookieName,"")
                .path("/")
                .httpOnly(true)
                .maxAge(0)
                .build();
    }
}
