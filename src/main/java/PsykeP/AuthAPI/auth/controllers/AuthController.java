package PsykeP.AuthAPI.auth.controllers;

import PsykeP.AuthAPI.auth.dtos.AuthResponseDTO;
import PsykeP.AuthAPI.auth.dtos.LoginRequestDTO;
import PsykeP.AuthAPI.auth.dtos.RegisterRequestDTO;
import PsykeP.AuthAPI.auth.dtos.UsuarioDTO;
import PsykeP.AuthAPI.auth.services.AuthService;
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
    public ResponseEntity<AuthResponseDTO> login(@Valid @RequestBody LoginRequestDTO request, HttpServletResponse response) {
        return ResponseEntity.ok(authService.login(request, response));
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponseDTO> register(@Valid @RequestBody RegisterRequestDTO request, HttpServletResponse response) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registrar(request, response));
    }

    @GetMapping("/me")
    public ResponseEntity<UsuarioDTO> me(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }
        UsuarioDTO perfil = authService.obtenerPerfil(authentication.getName());
        return ResponseEntity.ok(perfil);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        authService.logout(response);
        return ResponseEntity.ok().build();
    }
}
