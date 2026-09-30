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
                // 1. Integración explícita de la configuración CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource))

                // 2. Desactivación de CSRF y formulaciones tradicionales (Stateless API)
                .csrf(csrf -> csrf.disable())
                .httpBasic(httpBasic -> httpBasic.disable())
                .formLogin(form -> form.disable())

                // 3. Manejo de excepciones personalizadas para solicitudes no autenticadas
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED);
                            response.setContentType("application/json");
                            response.getWriter().write("{\"status\":401,\"error\":\"Unauthorized\",\"message\":\"No autenticado\"}");
                        })
                )

                // 4. Configuración de autorización de rutas
                .authorizeHttpRequests(auth -> auth
                        // Permitir siempre preflight HTTP OPTIONS para CORS
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // Permitir rutas de autenticación públicas (soporta con y sin prefijo /api/auth)
                        .requestMatchers("/login", "/register", "/api/auth/login", "/api/auth/register").permitAll()

                        // Proteger rutas de consulta de perfil
                        .requestMatchers("/api/auth/me", "/me").authenticated()

                        // Permitir cualquier otra subruta pública de auth
                        .requestMatchers("/api/auth/**").permitAll()

                        // Cualquier otra solicitud requiere autenticación
                        .anyRequest().authenticated()
                )

                // 5. Gestión de sesión sin estado (Stateless por JWT)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}