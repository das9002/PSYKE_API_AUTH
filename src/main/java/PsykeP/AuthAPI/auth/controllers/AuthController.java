package PsykeP.AuthAPI.auth.controllers;

import PsykeP.AuthAPI.auth.dtos.AuthResponseDTO;
import PsykeP.AuthAPI.auth.dtos.LoginRequestDTO;
import PsykeP.AuthAPI.auth.dtos.RecuperacionResponseDTO;
import PsykeP.AuthAPI.auth.dtos.RecuperarContrasenaDTO;
import PsykeP.AuthAPI.auth.dtos.RegisterRequestDTO;
import PsykeP.AuthAPI.auth.dtos.RestablecerContrasenaDTO;
import PsykeP.AuthAPI.auth.dtos.TicketChatDTO;
import PsykeP.AuthAPI.auth.dtos.UsuarioDTO;
import PsykeP.AuthAPI.auth.dtos.VerificarCodigoDTO;
import PsykeP.AuthAPI.auth.services.AuthService;
import PsykeP.AuthAPI.common.respuestas.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponseDTO>> login(@Valid @RequestBody LoginRequestDTO request, HttpServletResponse response) {
        return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK, "Sesión iniciada correctamente.", authService.login(request, response)));
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponseDTO>> register(@Valid @RequestBody RegisterRequestDTO request, HttpServletResponse response) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new ApiResponse<>(HttpStatus.CREATED, "Usuario registrado correctamente.", authService.registrar(request, response)));
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UsuarioDTO>> me(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(HttpStatus.UNAUTHORIZED, "No hay una sesión activa."));
        }
        UsuarioDTO perfil = authService.obtenerPerfil(authentication.getName());
        return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK, "Perfil obtenido correctamente.", perfil));
    }

    @GetMapping("/usuarios")
    public ResponseEntity<ApiResponse<org.springframework.data.domain.Page<UsuarioDTO>>> listarUsuarios(
            @org.springframework.data.web.PageableDefault(size = 10) org.springframework.data.domain.Pageable pageable) {
        return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK, "Consulta realizada correctamente.", authService.listarUsuariosPaginados(pageable)));
    }

    @PostMapping("/ws-ticket")
    public ResponseEntity<ApiResponse<TicketChatDTO>> ticketChat(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(HttpStatus.UNAUTHORIZED, "No hay una sesión activa."));
        }
        return ResponseEntity.ok()
                .header("Cache-Control", "no-store")
                .body(new ApiResponse<>(HttpStatus.OK, "Ticket del chat generado.", authService.generarTicketChat(authentication.getName())));
    }

    @PostMapping("/renovar")
    public ResponseEntity<ApiResponse<AuthResponseDTO>> renovar(Authentication authentication,
                                                                 HttpServletRequest request,
                                                                 HttpServletResponse response) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(HttpStatus.UNAUTHORIZED, "No hay una sesión activa."));
        }
        String cabecera = request.getHeader("Authorization");
        boolean conCookie = cabecera == null || !cabecera.startsWith("Bearer ");
        return ResponseEntity.ok()
                .header("Cache-Control", "no-store")
                .body(new ApiResponse<>(HttpStatus.OK, "Sesión renovada.", authService.renovarSesion(authentication.getName(), conCookie, response)));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletResponse response) {
        authService.logout(response);
        return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK, "Sesión cerrada correctamente."));
    }

    @PostMapping("/recuperar-contrasena")
    public ResponseEntity<ApiResponse<RecuperacionResponseDTO>> solicitarRecuperacionContrasena(
            @Valid @RequestBody RecuperarContrasenaDTO request) {
        RecuperacionResponseDTO resultado = authService.solicitarRecuperacionContrasena(request);
        return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK, resultado.getMessage(), resultado));
    }

    @PostMapping("/verificar-codigo")
    public ResponseEntity<ApiResponse<RecuperacionResponseDTO>> verificarCodigo(@Valid @RequestBody VerificarCodigoDTO request) {
        RecuperacionResponseDTO resultado = authService.verificarCodigoRecuperacion(request);
        return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK, resultado.getMessage(), resultado));
    }

    @PostMapping("/restablecer-contrasena")
    public ResponseEntity<ApiResponse<RecuperacionResponseDTO>> restablecerContrasena(@Valid @RequestBody RestablecerContrasenaDTO request) {
        RecuperacionResponseDTO resultado = authService.restablecerContrasena(request);
        return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK, resultado.getMessage(), resultado));
    }
}
