package PsykeP.AuthAPI.exceptions;

import org.springframework.http.HttpStatus;

import java.util.Map;

public class RecuperacionException extends RuntimeException {

    private final HttpStatus status;
    private final Map<String, String> detalles;

    public RecuperacionException(HttpStatus status, String message) {
        this(status, message, null);
    }

    public RecuperacionException(HttpStatus status, String message, Map<String, String> detalles) {
        super(message);
        this.status = status;
        this.detalles = detalles;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public Map<String, String> getDetalles() {
        return detalles;
    }
}
