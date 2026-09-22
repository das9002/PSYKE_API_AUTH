package PsykeP.AuthAPI.auth.controllers;

import PsykeP.AuthAPI.auth.dtos.AuthResponseDTO;
import PsykeP.AuthAPI.auth.dtos.LoginRequestDTO;
import PsykeP.AuthAPI.auth.dtos.RegisterRequestDTO;
import PsykeP.AuthAPI.auth.dtos.UsuarioDTO;
import PsykeP.AuthAPI.auth.services.AuthService;
import PsykeP.AuthAPI.exceptions.CredencialesInvalidasException;
import PsykeP.AuthAPI.exceptions.GlobalExceptionHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    private MockMvc mockMvc;

    @Mock
    private AuthService authService;

    @InjectMocks
    private AuthController authController;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(authController)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void testLogin_Exitoso() throws Exception {
        LoginRequestDTO request = LoginRequestDTO.builder()
                .correo("test@example.com")
                .contrasena("password123")
                .origen("WEB")
                .build();

        AuthResponseDTO responseDTO = AuthResponseDTO.builder()
                .tipoToken("Bearer")
                .idUsuario(1L)
                .correo("test@example.com")
                .tipoUsuario("PSICOLOGO")
                .expiraEn(900000L)
                .build();

        when(authService.login(any(), any())).thenReturn(responseDTO);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.idUsuario").value(1))
                .andExpect(jsonPath("$.correo").value("test@example.com"))
                .andExpect(jsonPath("$.tipoUsuario").value("PSICOLOGO"));
    }

    @Test
    void testLogin_ValidacionFallida_CampoInvalido() throws Exception {
        LoginRequestDTO request = LoginRequestDTO.builder()
                .correo("formato-invalido")
                .contrasena("")
                .build();

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details.correo").exists())
                .andExpect(jsonPath("$.details.contrasena").exists());
    }

    @Test
    void testLogin_CredencialesInvalidas() throws Exception {
        LoginRequestDTO request = LoginRequestDTO.builder()
                .correo("test@example.com")
                .contrasena("wrongpass")
                .build();

        when(authService.login(any(), any())).thenThrow(new CredencialesInvalidasException("Credenciales inválidas"));

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Credenciales inválidas"));
    }

    @Test
    void testRegister_Exitoso() throws Exception {
        RegisterRequestDTO request = RegisterRequestDTO.builder()
                .correo("nuevo@example.com")
                .contrasena("Password123")
                .tipoUsuario("ESTUDIANTE")
                .build();

        AuthResponseDTO responseDTO = AuthResponseDTO.builder()
                .tipoToken("Bearer")
                .idUsuario(2L)
                .correo("nuevo@example.com")
                .tipoUsuario("ESTUDIANTE")
                .expiraEn(900000L)
                .build();

        when(authService.registrar(any(), any())).thenReturn(responseDTO);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.idUsuario").value(2))
                .andExpect(jsonPath("$.correo").value("nuevo@example.com"));
    }

    @Test
    void testMe_Autenticado() throws Exception {
        Authentication auth = new UsernamePasswordAuthenticationToken("user@example.com", null, java.util.List.of());
        UsuarioDTO usuarioDTO = UsuarioDTO.builder()
                .idUsuario(1L)
                .correo("user@example.com")
                .estadoCuenta("ACTIVO")
                .tipoUsuario("ESTUDIANTE")
                .build();

        when(authService.obtenerPerfil("user@example.com")).thenReturn(usuarioDTO);

        mockMvc.perform(get("/api/auth/me").principal(auth))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.idUsuario").value(1))
                .andExpect(jsonPath("$.correo").value("user@example.com"));
    }

    @Test
    void testMe_NoAutenticado() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testLogout() throws Exception {
        mockMvc.perform(post("/api/auth/logout"))
                .andExpect(status().isOk());
    }
}
