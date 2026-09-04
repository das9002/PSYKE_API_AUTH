package PsykeP.AuthAPI.auth.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponseDTO {

    private String tipoToken;
    private Long idUsuario;
    private String correo;
    private String tipoUsuario;
    private long expiraEn;
}
