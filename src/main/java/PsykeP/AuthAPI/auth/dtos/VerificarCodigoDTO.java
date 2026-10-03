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
public class VerificarCodigoDTO {

    @NotBlank(message = "El correo es requerido")
    @Email(message = "Debe ser un correo electrónico válido")
    private String correo;

    @NotBlank(message = "El código es requerido")
    @Pattern(regexp = "\\d{6}", message = "El código debe tener 6 dígitos")
    private String codigo;
}
