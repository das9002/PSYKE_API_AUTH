package PsykeP.AuthAPI.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final CorsConfigurationSource corsConfigurationSource;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 1. Integración de la configuración CORS usando el Bean inyectado de CorsConfig
            .cors(cors -> cors.configurationSource(corsConfigurationSource))

            // 2. Desactivación de CSRF, HTTP Basic y Form Login tradicional (API REST Stateless)
            .csrf(csrf -> csrf.disable())
            .httpBasic(httpBasic -> httpBasic.disable())
            .formLogin(form -> form.disable())

            // 3. Manejo de excepciones personalizadas para solicitudes no autenticadas (Respuesta 401 en JSON)
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"status\":401,\"error\":\"Unauthorized\",\"message\":\"No autenticado\"}");
                })
            )

            // 4. Configuración de autorización de rutas (Evaluación en orden descendente)
            .authorizeHttpRequests(auth -> auth
                // Permitir siempre preflight HTTP OPTIONS para CORS
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                // Permitir rutas de autenticación públicas (soporta con y sin el prefijo /api/auth)
                .requestMatchers(
                    "/login", "/register", "/logout",
                    "/api/auth/login", "/api/auth/register", "/api/auth/logout"
                ).permitAll()

                // Proteger explícitamente las rutas de consulta de perfil de usuario
                .requestMatchers("/api/auth/me", "/me").authenticated()

                // Permitir cualquier otra subruta de autenticación pública no especificada arriba
                .requestMatchers("/api/auth/**").permitAll()

                // Cualquier otra solicitud en la aplicación requiere autenticación
                .anyRequest().authenticated()
            )

            // 5. Gestión de sesión sin estado (Stateless por JWT)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // 6. Proveedor de autenticación y filtro JWT personalizado
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
