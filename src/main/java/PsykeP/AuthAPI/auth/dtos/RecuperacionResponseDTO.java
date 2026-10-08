package PsykeP.AuthAPI.auth.dtos;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RecuperacionResponseDTO {

    private String message;
    private Long expiraEnSegundos;
    private Long reenvioEnSegundos;
    private String tokenRestablecimiento;
}
