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

    // La app móvil guarda el token en el almacenamiento seguro del teléfono: dura más para no pedir login a cada rato
    @Value("${security.jwt.expiration-time-movil:2592000000}")
    private long jwtExpirationMovil;

    public long getJwtExpiration() {
        return jwtExpiration;
    }

    public long getJwtExpirationMovil() {
        return jwtExpirationMovil;
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
        return generarToken(userDetails, jwtExpiration);
    }

    public String generarToken(UserDetails userDetails, long duracionMs) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", userDetails.getAuthorities());
        // La API principal lee el id del token y así no consulta la tabla USUARIOS en cada petición
        if (userDetails instanceof Usuario usuario) {
            claims.put("idUsuario", usuario.getIdUsuario());
            claims.put("tipoUsuario", usuario.getTipoUsuario());
        }
        return crearToken(claims, userDetails.getUsername(), duracionMs);
    }

    private String crearToken(Map<String, Object> claims, String subject, long duracionMs) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + duracionMs))
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

    /** Verifica firma y expiración (lanza JwtException si el token no es válido) y devuelve los claims. */
    public Claims extraerTodosLosClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean esTokenValido(String token) {
        return esTokenValido(extraerTodosLosClaims(token));
    }

    /** Igual que esTokenValido(String) pero con los claims ya leídos, para no analizar el token varias veces. */
    public boolean esTokenValido(Claims claims) {
        final String username = claims.getSubject();
        if (username == null || claims.getExpiration() == null || claims.getExpiration().before(new Date())) {
            return false;
        }
        if (TIPO_TICKET_CHAT.equals(claims.get("tipo", String.class))) {
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

    // La clave se calcula una sola vez en lugar de decodificarla en cada petición
    private volatile Key signingKey;

    private Key getSigningKey() {
        Key clave = signingKey;
        if (clave == null) {
            clave = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
            signingKey = clave;
        }
        return clave;
    }
}
