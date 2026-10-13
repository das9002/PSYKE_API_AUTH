package PsykeP.AuthAPI.exceptions;

import PsykeP.AuthAPI.common.respuestas.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Todas las respuestas de error usan ApiResponse: código de estado, mensaje para el usuario
 * y, cuando hace falta, el detalle (campos inválidos, segundos de espera, intentos restantes).
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(CredencialesInvalidasException.class)
    public ResponseEntity<ApiResponse<Void>> credencialesInvalidas(CredencialesInvalidasException ex) {
        return responder(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }

    @ExceptionHandler({UsuarioInactivoException.class, UsuarioBloqueadoException.class})
    public ResponseEntity<ApiResponse<Void>> usuarioSinAcceso(RuntimeException ex) {
        return responder(HttpStatus.FORBIDDEN, ex.getMessage());
    }

    @ExceptionHandler(UsuarioNoEncontradoException.class)
    public ResponseEntity<ApiResponse<Void>> usuarioNoEncontrado(UsuarioNoEncontradoException ex) {
        return responder(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    @ExceptionHandler(CorreoYaRegistradoException.class)
    public ResponseEntity<ApiResponse<Void>> correoRegistrado(CorreoYaRegistradoException ex) {
        return responder(HttpStatus.CONFLICT, ex.getMessage());
    }

    @ExceptionHandler(RecuperacionException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> recuperacion(RecuperacionException ex) {
        Map<String, String> detalles = ex.getDetalles();
        return ResponseEntity.status(ex.getStatus())
                .body(new ApiResponse<>(ex.getStatus(), ex.getMessage(), detalles == null || detalles.isEmpty() ? null : detalles));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiResponse<Void>> integridad(DataIntegrityViolationException ex) {
        log.warn("Restricción de integridad: {}", ex.getMostSpecificCause().getMessage());
        return responder(HttpStatus.CONFLICT, "No se puede completar la operación porque el registro está relacionado con otros datos.");
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ApiResponse<Void>> conEstado(ResponseStatusException ex) {
        HttpStatus status = HttpStatus.resolve(ex.getStatusCode().value());
        if (status == null) status = HttpStatus.BAD_REQUEST;
        return responder(status, ex.getReason() != null ? ex.getReason() : status.getReasonPhrase());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> camposInvalidos(MethodArgumentNotValidException ex) {
        Map<String, String> errores = new LinkedHashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String campo = (error instanceof FieldError fieldError) ? fieldError.getField() : error.getObjectName();
            errores.putIfAbsent(campo, error.getDefaultMessage());
        });
        String primero = errores.values().stream().findFirst().orElse("Revisa los datos ingresados.");
        return ResponseEntity.badRequest().body(new ApiResponse<>(HttpStatus.BAD_REQUEST, primero, errores));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Void>> formatoInvalido(HttpMessageNotReadableException ex) {
        return responder(HttpStatus.BAD_REQUEST, "Los datos enviados no tienen un formato válido.");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> inesperado(Exception ex) {
        log.error("Error interno no controlado", ex);
        return responder(HttpStatus.INTERNAL_SERVER_ERROR, "Ocurrió un error inesperado en el servidor. Intenta de nuevo más tarde.");
    }

    private ResponseEntity<ApiResponse<Void>> responder(HttpStatus status, String mensaje) {
        return ResponseEntity.status(status).body(new ApiResponse<>(status, mensaje));
    }
}
