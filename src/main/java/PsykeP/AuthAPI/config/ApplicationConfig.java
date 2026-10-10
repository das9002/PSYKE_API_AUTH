package PsykeP.AuthAPI.config;

import PsykeP.AuthAPI.auth.entities.Usuario;
import PsykeP.AuthAPI.auth.repositories.UsuarioRepository;
import PsykeP.AuthAPI.security.Argon2PasswordEncoderAcotado;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UsuarioRepository usuarioRepository;

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> usuarioRepository.findByCorreo(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        // Tras un login correcto con un hash antiguo (Argon2 de 64 MB), se guarda uno nuevo de 16 MB
        authProvider.setUserDetailsPasswordService(actualizadorDeContrasenas());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Antes: Argon2 con 64 MB por cálculo y sin límite de concurrencia (varios logins a la vez agotaban el heap)
        return new Argon2PasswordEncoderAcotado();
    }

    @Bean
    public org.springframework.cache.CacheManager cacheManager() {
        return new org.springframework.cache.concurrent.ConcurrentMapCacheManager("perfiles");
    }

    private UserDetailsPasswordService actualizadorDeContrasenas() {
        return (usuarioAutenticado, nuevaContrasena) -> {
            Usuario usuario = usuarioRepository.findByCorreo(usuarioAutenticado.getUsername()).orElse(null);
            if (usuario == null) {
                return usuarioAutenticado;
            }
            usuario.setContrasena(nuevaContrasena);
            return usuarioRepository.save(usuario);
        };
    }
}
