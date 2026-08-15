package PsykeP.AuthAPI.exceptions;

public class UsuarioBloqueadoException extends RuntimeException {

    public UsuarioBloqueadoException(String message) {
        super(message);
    }
}
