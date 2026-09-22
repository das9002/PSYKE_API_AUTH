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
import PsykeP.AuthAPI.security.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UsuarioRepository usuarioRepository;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtService jwtService;

    @Mock
    private org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    @Test
    void testLogin_Exitoso() {
        LoginRequestDTO loginRequest = LoginRequestDTO.builder()
                .correo("test@example.com")
                .contrasena("password123")
                .origen("WEB")
                .build();

        Usuario usuario = Usuario.builder()
                .idUsuario(1L)
                .correo("test@example.com")
                .contrasena("hashedPassword")
                .estadoCuenta("ACTIVO")
                .tipoUsuario("PSICOLOGO")
                .build();

        HttpServletResponse response = new MockHttpServletResponse();

        when(usuarioRepository.findByCorreo("test@example.com")).thenReturn(Optional.of(usuario));
        when(jwtService.generarToken(usuario)).thenReturn("mockToken");
        when(jwtService.getJwtExpiration()).thenReturn(900000L);

        AuthResponseDTO responseDTO = authService.login(loginRequest, response);

        assertNotNull(responseDTO);
        assertEquals("test@example.com", responseDTO.getCorreo());
        assertEquals("PSICOLOGO", responseDTO.getTipoUsuario());
        assertEquals("Bearer", responseDTO.getTipoToken());
        verify(authenticationManager).authenticate(any());
    }

    @Test
    void testLogin_UsuarioNoExiste_LanzaCredencialesInvalidas() {
        LoginRequestDTO loginRequest = LoginRequestDTO.builder()
                .correo("nonexistent@example.com")
                .contrasena("password123")
                .build();

        HttpServletResponse response = new MockHttpServletResponse();

        when(usuarioRepository.findByCorreo("nonexistent@example.com")).thenReturn(Optional.empty());

        assertThrows(CredencialesInvalidasException.class, () -> authService.login(loginRequest, response));
    }

    @Test
    void testLogin_UsuarioBloqueado_LanzaUsuarioBloqueadoException() {
        LoginRequestDTO loginRequest = LoginRequestDTO.builder()
                .correo("bloqueado@example.com")
                .contrasena("password123")
                .build();

        Usuario usuario = Usuario.builder()
                .idUsuario(1L)
                .correo("bloqueado@example.com")
                .contrasena("hashedPassword")
                .estadoCuenta("BLOQUEADO")
                .tipoUsuario("ESTUDIANTE")
                .build();

        HttpServletResponse response = new MockHttpServletResponse();

        when(usuarioRepository.findByCorreo("bloqueado@example.com")).thenReturn(Optional.of(usuario));

        assertThrows(UsuarioBloqueadoException.class, () -> authService.login(loginRequest, response));
    }

    @Test
    void testLogin_UsuarioInactivo_LanzaUsuarioInactivoException() {
        LoginRequestDTO loginRequest = LoginRequestDTO.builder()
                .correo("inactivo@example.com")
                .contrasena("password123")
                .build();

        Usuario usuario = Usuario.builder()
                .idUsuario(1L)
                .correo("inactivo@example.com")
                .contrasena("hashedPassword")
                .estadoCuenta("INACTIVO")
                .tipoUsuario("ESTUDIANTE")
                .build();

        HttpServletResponse response = new MockHttpServletResponse();

        when(usuarioRepository.findByCorreo("inactivo@example.com")).thenReturn(Optional.of(usuario));

        assertThrows(UsuarioInactivoException.class, () -> authService.login(loginRequest, response));
    }

    @Test
    void testLogin_ContrasenaIncorrecta_LanzaCredencialesInvalidas() {
        LoginRequestDTO loginRequest = LoginRequestDTO.builder()
                .correo("test@example.com")
                .contrasena("wrongpassword")
                .build();

        Usuario usuario = Usuario.builder()
                .idUsuario(1L)
                .correo("test@example.com")
                .contrasena("hashedPassword")
                .estadoCuenta("ACTIVO")
                .tipoUsuario("ESTUDIANTE")
                .build();

        HttpServletResponse response = new MockHttpServletResponse();

        when(usuarioRepository.findByCorreo("test@example.com")).thenReturn(Optional.of(usuario));
        doThrow(new BadCredentialsException("Bad credentials"))
                .when(authenticationManager).authenticate(any());

        assertThrows(CredencialesInvalidasException.class, () -> authService.login(loginRequest, response));
    }

    @Test
    void testRegistrar_Exitoso() {
        RegisterRequestDTO registerRequest = RegisterRequestDTO.builder()
                .correo("nuevo@example.com")
                .contrasena("Password123")
                .tipoUsuario("ESTUDIANTE")
                .build();

        Usuario usuarioGuardado = Usuario.builder()
                .idUsuario(2L)
                .correo("nuevo@example.com")
                .contrasena("encodedPassword")
                .estadoCuenta("ACTIVO")
                .tipoUsuario("ESTUDIANTE")
                .build();

        HttpServletResponse response = new MockHttpServletResponse();

        when(usuarioRepository.existsByCorreo("nuevo@example.com")).thenReturn(false);
        when(passwordEncoder.encode("Password123")).thenReturn("encodedPassword");
        when(usuarioRepository.save(any(Usuario.class))).thenReturn(usuarioGuardado);
        when(jwtService.generarToken(usuarioGuardado)).thenReturn("mockToken");
        when(jwtService.getJwtExpiration()).thenReturn(900000L);

        AuthResponseDTO responseDTO = authService.registrar(registerRequest, response);

        assertNotNull(responseDTO);
        assertEquals("nuevo@example.com", responseDTO.getCorreo());
        assertEquals("ESTUDIANTE", responseDTO.getTipoUsuario());
    }

    @Test
    void testRegistrar_CorreoYaExiste_LanzaCorreoYaRegistradoException() {
        RegisterRequestDTO registerRequest = RegisterRequestDTO.builder()
                .correo("existente@example.com")
                .contrasena("Password123")
                .tipoUsuario("ESTUDIANTE")
                .build();

        HttpServletResponse response = new MockHttpServletResponse();

        when(usuarioRepository.existsByCorreo("existente@example.com")).thenReturn(true);

        assertThrows(CorreoYaRegistradoException.class, () -> authService.registrar(registerRequest, response));
    }

    @Test
    void testObtenerPerfil_Exitoso() {
        Usuario usuario = Usuario.builder()
                .idUsuario(1L)
                .correo("perfil@example.com")
                .estadoCuenta("ACTIVO")
                .tipoUsuario("PSICOLOGO")
                .build();

        when(usuarioRepository.findByCorreo("perfil@example.com")).thenReturn(Optional.of(usuario));

        UsuarioDTO usuarioDTO = authService.obtenerPerfil("perfil@example.com");

        assertNotNull(usuarioDTO);
        assertEquals(1L, usuarioDTO.getIdUsuario());
        assertEquals("perfil@example.com", usuarioDTO.getCorreo());
        assertEquals("PSICOLOGO", usuarioDTO.getTipoUsuario());
    }
}
