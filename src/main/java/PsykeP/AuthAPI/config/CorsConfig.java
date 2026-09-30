package PsykeP.AuthAPI.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.List;

@Configuration
public class CorsConfig {

    // Se utiliza sintaxis SpEL segura para evitar que las comas del valor por defecto rompan la inyección
    @Value("${cors.allowed-origins:#{null}}")
    private String allowedOrigins;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        List<String> origins;
        
        // Si existe la variable en Heroku/application.properties, se parsea.
        // Si no existe, se utiliza la lista de fallback completa.
        if (allowedOrigins != null && !allowedOrigins.trim().isEmpty()) {
            origins = Arrays.stream(allowedOrigins.split(","))
                    .map(String::trim)
                    .filter(origin -> !origin.isEmpty())
                    .toList();
        } else {
            origins = List.of(
                    "https://psykeweb.vercel.app",
                    "https://*.vercel.app",
                    "https://api-service-4d465a47b94c.herokuapp.com",
                    "http://localhost",
                    "http://localhost:*",
                    "http://127.0.0.1",
                    "http://127.0.0.1:*"
            );
        }

        config.setAllowedOriginPatterns(origins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("Set-Cookie", "Authorization"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilterRegistrationBean(CorsConfigurationSource corsConfigurationSource) {
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(corsConfigurationSource));
        // Prioridad máxima absoluta para capturar las peticiones OPTIONS antes de Spring Security
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }
}
