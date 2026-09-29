package PsykeP.AuthAPI.auth.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequestDTO {

    @NotBlank(message = "El correo es obligatorio")
    @Email(message = "El correo debe tener un formato válido")
    private String correo;

    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 8, max = 64, message = "La contraseña debe tener entre 8 y 64 caracteres")
    private String contrasena;

    @NotBlank(message = "El tipo de usuario es obligatorio")
    @Pattern(regexp = "ESTUDIANTE|PSICOLOGO|ADMIN",
            message = "El tipo de usuario debe ser ESTUDIANTE, PSICOLOGO o ADMIN")
    private String tipoUsuario;
}
