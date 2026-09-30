package PsykeP.AuthAPI.security;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private static final String JWT_COOKIE_NAME = "psyke_auth_jwt";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Ignorar peticiones de pre-flight CORS
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        
        // Usar getServletPath() en lugar de getRequestURI() para evitar fallos si hay Context Path
        String path = request.getServletPath();
        
        // Omitir el filtro SOLO en endpoints públicos de autenticación
        return "/api/auth/login".equals(path) 
            || "/api/auth/register".equals(path)
            || "/api/auth/recuperar-password".equals(path)
            || "/api/auth/reset-password".equals(path);
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String jwt = extractJwt(request);

        if (jwt == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            final String userEmail = jwtService.extraerUsername(jwt);

            if (userEmail != null
                    && SecurityContextHolder.getContext().getAuthentication() == null
                    && jwtService.esTokenValido(jwt)) {

                Collection<? extends GrantedAuthority> authorities = extraerAuthorities(jwt);

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userEmail,
                        null,
                        authorities
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("Error al validar token JWT en petición [{}]: {}", request.getRequestURI(), ex.getMessage());
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private String extractJwt(HttpServletRequest request) {
        // 1. Extraer del Header Authorization
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7).trim();
            // Filtrar valores inválidos que a veces el frontend envía por error
            if (!token.isEmpty() && !"null".equalsIgnoreCase(token) && !"undefined".equalsIgnoreCase(token)) {
                return token;
            }
        }

        // 2. Fallback: Extraer de Cookie HttpOnly
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (JWT_COOKIE_NAME.equals(cookie.getName())) {
                    String value = cookie.getValue();
                    if (value != null && !value.isBlank()) {
                        return value;
                    }
                }
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Collection<? extends GrantedAuthority> extraerAuthorities(String jwt) {
        return jwtService.extraerClaim(jwt, claims -> {
            // A. Soporte para claim "roles" como Lista
            Object rolesObj = claims.get("roles");
            if (rolesObj instanceof List<?> roles) {
                return roles.stream()
                        .map(role -> {
                            if (role instanceof Map<?, ?> map) {
                                Object auth = map.get("authority");
                                return auth != null ? new SimpleGrantedAuthority(String.valueOf(auth)) : null;
                            } else if (role instanceof String str) {
                                return new SimpleGrantedAuthority(str.startsWith("ROLE_") ? str : "ROLE_" + str);
                            }
                            return null;
                        })
                        .filter(Objects::nonNull)
                        .collect(Collectors.toList());
            }

            // B. Soporte para claim individual "tipoUsuario" o "rol"
            String singleRole = claims.get("tipoUsuario", String.class);
            if (singleRole == null) {
                singleRole = claims.get("rol", String.class);
            }
            if (singleRole != null && !singleRole.isBlank()) {
                String roleFormatted = singleRole.startsWith("ROLE_") ? singleRole : "ROLE_" + singleRole;
                return List.of(new SimpleGrantedAuthority(roleFormatted));
            }

            return List.<GrantedAuthority>of();
        });
    }
}
