package PsykeP.AuthAPI.auth.services;

import PsykeP.AuthAPI.auth.dtos.AuthResponseDTO;
import PsykeP.AuthAPI.auth.dtos.LoginRequestDTO;
import PsykeP.AuthAPI.auth.dtos.RegisterRequestDTO;
import PsykeP.AuthAPI.auth.dtos.RestablecerContrasenaDTO;
import PsykeP.AuthAPI.auth.dtos.UsuarioDTO;
import PsykeP.AuthAPI.auth.entities.Usuario;
import PsykeP.AuthAPI.auth.repositories.UsuarioRepository;
import PsykeP.AuthAPI.exceptions.CorreoYaRegistradoException;
import PsykeP.AuthAPI.exceptions.CredencialesInvalidasException;
import PsykeP.AuthAPI.exceptions.UsuarioBloqueadoException;
import PsykeP.AuthAPI.exceptions.UsuarioInactivoException;
import PsykeP.AuthAPI.security.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final UsuarioRepository usuarioRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Transactional
    public AuthResponseDTO login(LoginRequestDTO request, HttpServletResponse response) {
        Usuario usuario = usuarioRepository.findByCorreo(request.getCorreo())
                .orElseThrow(() -> new CredencialesInvalidasException("Credenciales inválidas"));

        validarEstadoCuenta(usuario);

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getCorreo(), request.getContrasena())
            );
        } catch (BadCredentialsException ex) {
            throw new CredencialesInvalidasException("Credenciales inválidas");
        }

        validarOrigen(request.getOrigen(), usuario.getTipoUsuario());

        usuario.setUltimaConexion(LocalDateTime.now());

        final String token = jwtService.generarToken(usuario);

        ResponseCookie cookie = ResponseCookie.from("psyke_auth_jwt", token)
                .httpOnly(true)
                .secure(esEntornoSeguro())
                .sameSite(esEntornoSeguro() ? "None" : "Lax")
                .path("/")
                .maxAge(Duration.ofMillis(jwtService.getJwtExpiration()))
                .build();
        response.addHeader("Set-Cookie", cookie.toString());

        return AuthResponseDTO.builder()
                .token(token)
                .accessToken(token)
                .tipoToken("Bearer")
                .idUsuario(usuario.getIdUsuario())
                .correo(usuario.getCorreo())
                .tipoUsuario(usuario.getTipoUsuario())
                .expiraEn(jwtService.getJwtExpiration())
                .build();
    }

    @Transactional
    public AuthResponseDTO registrar(RegisterRequestDTO request, HttpServletResponse response) {
        if (usuarioRepository.existsByCorreo(request.getCorreo())) {
            throw new CorreoYaRegistradoException("Ya existe un usuario registrado con el correo: " + request.getCorreo());
        }

        Usuario usuario = Usuario.builder()
                .correo(request.getCorreo())
                .contrasena(passwordEncoder.encode(request.getContrasena()))
                .estadoCuenta("ACTIVO")
                .tipoUsuario(request.getTipoUsuario())
                .build();

        Usuario guardado = usuarioRepository.save(usuario);
        final String token = jwtService.generarToken(guardado);

        ResponseCookie cookie = ResponseCookie.from("psyke_auth_jwt", token)
                .httpOnly(true)
                .secure(esEntornoSeguro())
                .sameSite(esEntornoSeguro() ? "None" : "Lax")
                .path("/")
                .maxAge(Duration.ofMillis(jwtService.getJwtExpiration()))
                .build();
        response.addHeader("Set-Cookie", cookie.toString());

        return AuthResponseDTO.builder()
                .token(token)
                .accessToken(token)
                .tipoToken("Bearer")
                .idUsuario(guardado.getIdUsuario())
                .correo(guardado.getCorreo())
                .tipoUsuario(guardado.getTipoUsuario())
                .expiraEn(jwtService.getJwtExpiration())
                .build();
    }

    public UsuarioDTO obtenerPerfil(String correo) {
        Usuario usuario = usuarioRepository.findByCorreo(correo)
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Usuario no autenticado"));

        return UsuarioDTO.builder()
                .idUsuario(usuario.getIdUsuario())
                .correo(usuario.getCorreo())
                .estadoCuenta(usuario.getEstadoCuenta())
                .tipoUsuario(usuario.getTipoUsuario())
                .build();
    }

    public void logout(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from("psyke_auth_jwt", "")
                .httpOnly(true)
                .secure(esEntornoSeguro())
                .sameSite(esEntornoSeguro() ? "None" : "Lax")
                .path("/")
                .maxAge(0)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    @Transactional
    public void solicitarRecuperacionContrasena(String correo) {
        Usuario usuario = usuarioRepository.findByCorreo(correo)
                .orElseThrow(() -> new CredencialesInvalidasException("No existe una cuenta registrada con este correo."));

        validarEstadoCuenta(usuario);

        // Generar código numérico aleatorio de 6 dígitos
        String codigo = String.format("%06d", new SecureRandom().nextInt(1_000_000));

        // Guardar código y fecha de expiración (5 minutos)
        usuario.setCodigoRecuperacion(codigo);
        usuario.setFechaExpiracionCodigo(LocalDateTime.now().plusMinutes(5));
        usuarioRepository.save(usuario);

        // Enviar el correo con el código
        emailService.enviarCodigoRecuperacion(correo, codigo);
    }

    @Transactional
    public void restablecerContrasena(RestablecerContrasenaDTO request) {
        Usuario usuario = usuarioRepository.findByCorreo(request.getCorreo())
                .orElseThrow(() -> new CredencialesInvalidasException("No existe un usuario registrado con este correo."));

        // 1. Validar que exista y coincida el código de verificación
        if (usuario.getCodigoRecuperacion() == null || !usuario.getCodigoRecuperacion().equals(request.getCodigo())) {
            throw new CredencialesInvalidasException("El código de verificación es incorrecto.");
        }

        // 2. Validar que el código no haya expirado
        if (usuario.getFechaExpiracionCodigo() == null || usuario.getFechaExpiracionCodigo().isBefore(LocalDateTime.now())) {
            throw new CredencialesInvalidasException("El código de verificación ha expirado. Solicite uno nuevo.");
        }

        // 3. Encriptar y actualizar la nueva contraseña
        usuario.setContrasena(passwordEncoder.encode(request.getNuevaContrasena()));

        // 4. Limpiar los campos del código utilizado
        usuario.setCodigoRecuperacion(null);
        usuario.setFechaExpiracionCodigo(null);

        usuarioRepository.save(usuario);
    }

    private boolean esEntornoSeguro() {
        String env = System.getenv("SPRING_PROFILES_ACTIVE");
        return env != null && !env.contains("dev") && !env.contains("local");
    }

    private void validarEstadoCuenta(Usuario usuario) {
        if ("BLOQUEADO".equals(usuario.getEstadoCuenta())) {
            throw new UsuarioBloqueadoException("La cuenta se encuentra bloqueada. Contacte al administrador.");
        }
        if (!"ACTIVO".equals(usuario.getEstadoCuenta())) {
            throw new UsuarioInactivoException("La cuenta se encuentra inactiva. Contacte al administrador.");
        }
    }

    private void validarOrigen(String origen, String tipoUsuario) {
        if (origen == null) return;

        if ("WEB".equalsIgnoreCase(origen) && "ESTUDIANTE".equals(tipoUsuario)) {
            throw new ResponseStatusException(FORBIDDEN, "Los estudiantes no pueden acceder desde la web");
        }
        if ("MOBILE".equalsIgnoreCase(origen) && ("ADMIN".equals(tipoUsuario) || "PSICOLOGO".equals(tipoUsuario))) {
            throw new ResponseStatusException(FORBIDDEN, "Administradores y psicólogos no pueden acceder desde la app móvil");
        }
    }
}
