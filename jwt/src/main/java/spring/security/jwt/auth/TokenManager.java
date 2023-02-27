package spring.security.jwt.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TokenManager {

    private static final String secretKey = "LetMeCode";
    private static final int validity = 5 * 60 * 1000;

    public String generateToken(String userName) {
        return Jwts.builder()
                .setSubject(userName)
                .setIssuer("Kamran Baghirzada")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + validity))
                .signWith(SignatureAlgorithm.ES256, secretKey)
                .compact();
    }

    public boolean tokenValidate(String token) {
        return getUserFromToken(token) != null && isExpired(token);
    }

    public String getUserFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.getSubject();
    }

    public boolean isExpired(String token) {
        Claims claims = getClaims(token);
        return claims.getExpiration().before(new Date(System.currentTimeMillis()));
    }

    private static Claims getClaims(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }


}
