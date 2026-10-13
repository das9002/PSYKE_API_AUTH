package PsykeP.AuthAPI.common.respuestas;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

/**
 * Formato único de respuesta de la API.
 * Todas las respuestas, correctas o con error, llevan el código de estado, si salió bien,
 * un mensaje para mostrar en el frontend y, cuando aplica, los datos.
 */
@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {

    private final int status;
    private final boolean exito;
    private final String mensaje;
    private final T data;
    private final LocalDateTime fecha;

    /** Respuesta que contiene datos (consultas, registros creados o actualizados). */
    public ApiResponse(HttpStatus status, String mensaje, T data) {
        this.status = status.value();
        this.exito = status.is2xxSuccessful();
        this.mensaje = mensaje;
        this.data = data;
        this.fecha = LocalDateTime.now();
    }

    /** Respuesta sin datos (eliminaciones, confirmaciones y errores). */
    public ApiResponse(HttpStatus status, String mensaje) {
        this(status, mensaje, null);
    }
}
