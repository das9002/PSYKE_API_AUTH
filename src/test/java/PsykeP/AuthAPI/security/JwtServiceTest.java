package PsykeP.AuthAPI.security;

import PsykeP.AuthAPI.auth.entities.Usuario;
import PsykeP.AuthAPI.auth.repositories.UsuarioRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @Mock
    private UsuarioRepository usuarioRepository;

    @InjectMocks
    private JwtService jwtService;

    // Secret Key codificada en Base64 de 256 bits para HMAC-SHA256
    private final String secretKey = "dGhpc2lzYW1vY2tzZWNyZXRrZXlmb3Jqd3R0ZXN0aW5ncHVycG9zZXNvbmx5MTIzNDU2Nzg5MA==";
    private final long expiration = 900000L;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtService, "secretKey", secretKey);
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", expiration);
    }

    @Test
    void testGenerarYExtraerUsernameToken() {
        Usuario usuario = Usuario.builder()
                .idUsuario(1L)
                .correo("test@example.com")
                .tipoUsuario("ESTUDIANTE")
                .estadoCuenta("ACTIVO")
                .build();

        String token = jwtService.generarToken(usuario);

        assertNotNull(token);
        assertEquals("test@example.com", jwtService.extraerUsername(token));
    }

    @Test
    void testEsTokenValido_Exitoso() {
        Usuario usuario = Usuario.builder()
                .idUsuario(1L)
                .correo("test@example.com")
                .tipoUsuario("ESTUDIANTE")
                .estadoCuenta("ACTIVO")
                .build();

        when(usuarioRepository.findByCorreo("test@example.com")).thenReturn(Optional.of(usuario));

        String token = jwtService.generarToken(usuario);
        boolean valido = jwtService.esTokenValido(token);

        assertTrue(valido);
    }

    @Test
    void testEsTokenValido_UsuarioBloqueado() {
        Usuario usuario = Usuario.builder()
                .idUsuario(1L)
                .correo("test@example.com")
                .tipoUsuario("ESTUDIANTE")
                .estadoCuenta("BLOQUEADO")
                .build();

        when(usuarioRepository.findByCorreo("test@example.com")).thenReturn(Optional.of(usuario));

        String token = jwtService.generarToken(usuario);
        boolean valido = jwtService.esTokenValido(token);

        assertFalse(valido);
    }

    @Test
    void testEsTokenValido_UsuarioInactivo() {
        Usuario usuario = Usuario.builder()
                .idUsuario(1L)
                .correo("test@example.com")
                .tipoUsuario("ESTUDIANTE")
                .estadoCuenta("INACTIVO")
                .build();

        when(usuarioRepository.findByCorreo("test@example.com")).thenReturn(Optional.of(usuario));

        String token = jwtService.generarToken(usuario);
        boolean valido = jwtService.esTokenValido(token);

        assertFalse(valido);
    }

    @Test
    void testEsTokenValido_UsuarioNoExiste() {
        Usuario usuario = Usuario.builder()
                .idUsuario(1L)
                .correo("test@example.com")
                .tipoUsuario("ESTUDIANTE")
                .estadoCuenta("ACTIVO")
                .build();

        when(usuarioRepository.findByCorreo(anyString())).thenReturn(Optional.empty());

        String token = jwtService.generarToken(usuario);
        boolean valido = jwtService.esTokenValido(token);

        assertFalse(valido);
    }
}
