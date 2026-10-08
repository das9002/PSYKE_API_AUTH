package PsykeP.AuthAPI.auth.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
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

    @Pattern(regexp = "WEB|MOBILE", message = "El origen debe ser WEB o MOBILE")
    private String origen;
}
