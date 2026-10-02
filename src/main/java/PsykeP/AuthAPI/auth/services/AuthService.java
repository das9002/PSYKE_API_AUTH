package PsykeP.AuthAPI.auth.services;

import PsykeP.AuthAPI.auth.dtos.AuthResponseDTO;
import PsykeP.AuthAPI.auth.dtos.LoginRequestDTO;
import PsykeP.AuthAPI.auth.dtos.RecuperacionResponseDTO;
import PsykeP.AuthAPI.auth.dtos.RecuperarContrasenaDTO;
import PsykeP.AuthAPI.auth.dtos.RegisterRequestDTO;
import PsykeP.AuthAPI.auth.dtos.RestablecerContrasenaDTO;
import PsykeP.AuthAPI.auth.dtos.UsuarioDTO;
import PsykeP.AuthAPI.auth.dtos.VerificarCodigoDTO;
import PsykeP.AuthAPI.auth.entities.Usuario;
import PsykeP.AuthAPI.auth.repositories.UsuarioRepository;
import PsykeP.AuthAPI.exceptions.CorreoYaRegistradoException;
import PsykeP.AuthAPI.exceptions.CredencialesInvalidasException;
import PsykeP.AuthAPI.exceptions.RecuperacionException;
import PsykeP.AuthAPI.exceptions.UsuarioBloqueadoException;
import PsykeP.AuthAPI.exceptions.UsuarioInactivoException;
import PsykeP.AuthAPI.exceptions.UsuarioNoEncontradoException;
import PsykeP.AuthAPI.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.LocalDateTime;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private static final String COOKIE_SESION = "psyke_auth_jwt";

    private final UsuarioRepository usuarioRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final CodigoRecuperacionService codigoRecuperacionService;
    private final CorreoService correoService;

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
        escribirCookieSesion(response, token, Duration.ofMillis(jwtService.getJwtExpiration()));

        boolean esWeb = "WEB".equalsIgnoreCase(request.getOrigen());

        return AuthResponseDTO.builder()
                .token(esWeb ? null : token)
                .accessToken(esWeb ? null : token)
                .tipoToken(esWeb ? "Cookie" : "Bearer")
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
        escribirCookieSesion(response, token, Duration.ofMillis(jwtService.getJwtExpiration()));

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
        escribirCookieSesion(response, "", Duration.ZERO);
    }

    public RecuperacionResponseDTO solicitarRecuperacionContrasena(RecuperarContrasenaDTO request) {
        Usuario usuario = usuarioRepository.findByCorreo(request.getCorreo().trim())
                .orElseThrow(() -> new UsuarioNoEncontradoException("No existe una cuenta registrada con este correo."));

        validarEstadoCuenta(usuario);
        validarOrigen(request.getOrigen(), usuario.getTipoUsuario());

        String codigo = codigoRecuperacionService.generarCodigo(usuario.getCorreo());
        long minutos = codigoRecuperacionService.getSegundosExpiracion() / 60;

        if (!correoService.enviarCodigoRecuperacion(usuario.getCorreo(), codigo, minutos)) {
            codigoRecuperacionService.descartar(usuario.getCorreo());
            throw new RecuperacionException(HttpStatus.SERVICE_UNAVAILABLE,
                    "No se pudo enviar el correo en este momento. Intenta de nuevo en unos minutos.");
        }

        return RecuperacionResponseDTO.builder()
                .message("Enviamos un código de verificación a tu correo.")
                .expiraEnSegundos(codigoRecuperacionService.getSegundosExpiracion())
                .reenvioEnSegundos(codigoRecuperacionService.getSegundosReenvio())
                .build();
    }

    public RecuperacionResponseDTO verificarCodigoRecuperacion(VerificarCodigoDTO request) {
        String token = codigoRecuperacionService.verificarCodigo(request.getCorreo(), request.getCodigo());

        return RecuperacionResponseDTO.builder()
                .message("Código verificado. Ya puedes crear tu nueva contraseña.")
                .tokenRestablecimiento(token)
                .expiraEnSegundos(codigoRecuperacionService.getSegundosToken())
                .build();
    }

    @Transactional
    public RecuperacionResponseDTO restablecerContrasena(RestablecerContrasenaDTO request) {
        codigoRecuperacionService.validarToken(request.getCorreo(), request.getTokenRestablecimiento());

        Usuario usuario = usuarioRepository.findByCorreo(request.getCorreo().trim())
                .orElseThrow(() -> new UsuarioNoEncontradoException("No existe una cuenta registrada con este correo."));

        validarEstadoCuenta(usuario);

        if (passwordEncoder.matches(request.getNuevaContrasena(), usuario.getContrasena())) {
            throw new RecuperacionException(HttpStatus.BAD_REQUEST, "La nueva contraseña debe ser diferente a la anterior.");
        }

        usuario.setContrasena(passwordEncoder.encode(request.getNuevaContrasena()));
        usuarioRepository.save(usuario);
        codigoRecuperacionService.consumirToken(request.getCorreo());

        return RecuperacionResponseDTO.builder()
                .message("Tu contraseña se actualizó correctamente. Ya puedes iniciar sesión.")
                .build();
    }

    private void escribirCookieSesion(HttpServletResponse response, String valor, Duration duracion) {
        ResponseCookie cookie = ResponseCookie.from(COOKIE_SESION, valor)
                .httpOnly(true)
                .secure(esConexionSegura())
                .sameSite("Lax")
                .path("/")
                .maxAge(duracion)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private boolean esConexionSegura() {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes atributos)) {
            return false;
        }
        HttpServletRequest peticion = atributos.getRequest();
        return peticion.isSecure() || "https".equalsIgnoreCase(peticion.getHeader("X-Forwarded-Proto"));
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
