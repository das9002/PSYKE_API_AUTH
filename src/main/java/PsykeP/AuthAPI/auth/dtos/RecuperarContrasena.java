package PsykeP.AuthAPI.auth.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RecuperarContrasenaDTO {

    @NotBlank(message = "El correo es requerido")
    @Email(message = "Debe ser un correo electrónico válido")
    private String correo;
}