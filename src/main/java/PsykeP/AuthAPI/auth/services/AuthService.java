package PsykeP.AuthAPI.auth.services;

import PsykeP.AuthAPI.auth.dtos.AuthResponseDTO;
import PsykeP.AuthAPI.auth.dtos.LoginRequestDTO;
import PsykeP.AuthAPI.auth.dtos.RegisterRequestDTO;
import PsykeP.AuthAPI.auth.dtos.UsuarioDTO;
import PsykeP.AuthAPI.auth.entities.Usuario;
import PsykeP.AuthAPI.auth.repositories.UsuarioRepository;
import PsykeP.AuthAPI.exceptions.CorreoYaRegistradoException;
import PsykeP.AuthAPI.exceptions.CredencialesInvalidasException;
import PsykeP.AuthAPI.exceptions.UsuarioBloqueadoException;
import PsykeP.AuthAPI.exceptions.UsuarioInactivoException;
import PsykeP.AuthAPI.exceptions.UsuarioNoEncontradoException;
import PsykeP.AuthAPI.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final UsuarioRepository usuarioRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public AuthResponseDTO login(LoginRequestDTO request) {
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

        usuario.setUltimaConexion(LocalDateTime.now());

        final String token = jwtService.generarToken(usuario);

        return AuthResponseDTO.builder()
                .token(token)
                .tipoToken("Bearer")
                .idUsuario(usuario.getIdUsuario())
                .correo(usuario.getCorreo())
                .tipoUsuario(usuario.getTipoUsuario())
                .expiraEn(jwtService.getJwtExpiration())
                .build();
    }

    @Transactional
    public AuthResponseDTO registrar(RegisterRequestDTO request) {
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

        return AuthResponseDTO.builder()
                .token(token)
                .tipoToken("Bearer")
                .idUsuario(guardado.getIdUsuario())
                .correo(guardado.getCorreo())
                .tipoUsuario(guardado.getTipoUsuario())
                .expiraEn(jwtService.getJwtExpiration())
                .build();
    }

    public UsuarioDTO obtenerPerfil(String correo) {
        Usuario usuario = usuarioRepository.findByCorreo(correo)
                .orElseThrow(() -> new UsuarioNoEncontradoException("Usuario no encontrado con el correo: " + correo));

        return UsuarioDTO.builder()
                .idUsuario(usuario.getIdUsuario())
                .correo(usuario.getCorreo())
                .estadoCuenta(usuario.getEstadoCuenta())
                .tipoUsuario(usuario.getTipoUsuario())
                .build();
    }

    private void validarEstadoCuenta(Usuario usuario) {
        if ("BLOQUEADO".equals(usuario.getEstadoCuenta())) {
            throw new UsuarioBloqueadoException("La cuenta se encuentra bloqueada. Contacte al administrador.");
        }
        if (!"ACTIVO".equals(usuario.getEstadoCuenta())) {
            throw new UsuarioInactivoException("La cuenta se encuentra inactiva. Contacte al administrador.");
        }
    }
}
