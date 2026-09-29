package PsykeP.AuthAPI.security;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
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
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private static final String JWT_COOKIE_NAME = "psyke_auth_jwt";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Omite el filtro ÚNICAMENTE en peticiones preflight HTTP OPTIONS (necesario para CORS)
        return "OPTIONS".equalsIgnoreCase(request.getMethod());
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String jwt = extractJwt(request);

        if (jwt == null || jwt.isBlank()) {
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
            // Si el token es inválido, expiro o está malformado, limpiamos el contexto
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private String extractJwt(HttpServletRequest request) {
        // 1. Intentar obtener el token desde el encabezado Authorization
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7).trim();
            if (!token.isBlank()) {
                return token;
            }
        }

        // 2. Si no existe en el encabezado, intentar obtenerlo desde las Cookies
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
            Object rolesObj = claims.get("roles");
            if (rolesObj instanceof List<?> roles) {
                return roles.stream()
                        .map(role -> {
                            if (role instanceof Map<?, ?> map) {
                                return new SimpleGrantedAuthority(String.valueOf(map.get("authority")));
                            } else if (role instanceof String strRole) {
                                return new SimpleGrantedAuthority(strRole);
                            }
                            return null;
                        })
                        .filter(auth -> auth != null && !auth.getAuthority().isBlank())
                        .collect(Collectors.toList());
            }
            return List.of();
        });
    }
}