package PsykeP.AuthAPI.security;

import PsykeP.AuthAPI.auth.entities.Usuario;
import PsykeP.AuthAPI.auth.repositories.UsuarioRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final UsuarioRepository usuarioRepository;

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    // Valor por defecto asignado a 900000 milisegundos (15 minutos)
    @Value("${security.jwt.expiration-time:900000}")
    private long jwtExpiration;

    public static final String TIPO_TICKET_CHAT = "ws";
    private static final long DURACION_TICKET_CHAT_MS = 60_000;

    public long getJwtExpiration() {
        return jwtExpiration;
    }

    public long getDuracionTicketChatSegundos() {
        return DURACION_TICKET_CHAT_MS / 1000;
    }

    /**
     * Ticket de un solo uso para abrir la conexión WebSocket del chat.
     * Dura 60 segundos y lleva el claim tipo=ws para que no sirva como token de sesión.
     */
    public String generarTicketChat(Usuario usuario) {
        long ahora = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(usuario.getCorreo())
                .setId(UUID.randomUUID().toString())
                .claim("tipo", TIPO_TICKET_CHAT)
                .claim("idUsuario", usuario.getIdUsuario())
                .claim("tipoUsuario", usuario.getTipoUsuario())
                .setIssuedAt(new Date(ahora))
                .setExpiration(new Date(ahora + DURACION_TICKET_CHAT_MS))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generarToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", userDetails.getAuthorities());
        return crearToken(claims, userDetails.getUsername());
    }

    private String crearToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String extraerUsername(String token) {
        return extraerClaim(token, Claims::getSubject);
    }

    public <T> T extraerClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extraerTodosLosClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extraerTodosLosClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean esTokenValido(String token) {
        final String username = extraerUsername(token);
        if (username == null || esTokenExpirado(token)) {
            return false;
        }
        if (TIPO_TICKET_CHAT.equals(extraerClaim(token, claims -> claims.get("tipo", String.class)))) {
            return false;
        }
        Usuario usuario = usuarioRepository.findByCorreo(username).orElse(null);
        if (usuario == null) {
            return false;
        }
        if ("BLOQUEADO".equals(usuario.getEstadoCuenta())
                || !"ACTIVO".equals(usuario.getEstadoCuenta())) {
            return false;
        }
        return true;
    }

    private boolean esTokenExpirado(String token) {
        return extraerClaim(token, Claims::getExpiration).before(new Date());
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
