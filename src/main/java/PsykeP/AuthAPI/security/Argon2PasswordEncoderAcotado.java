package PsykeP.AuthAPI.security;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.concurrent.Semaphore;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Argon2 con un consumo de memoria acotado.
 *
 * Cada cálculo de Argon2 reserva en el heap la memoria indicada en el hash (antes m=65536 KiB = 64 MB),
 * así que varios logins simultáneos agotaban la memoria del dyno. Aquí los hashes nuevos usan 16 MB y
 * un semáforo limita la memoria total de los cálculos simultáneos a 64 MB: hasta 4 hashes nuevos a la
 * vez, o un solo hash antiguo de 64 MB.
 *
 * Los hashes antiguos siguen siendo válidos; upgradeEncoding() los marca para que el
 * DaoAuthenticationProvider los regenere con los parámetros nuevos al iniciar sesión.
 */
public class Argon2PasswordEncoderAcotado implements PasswordEncoder {

    private static final int LONGITUD_SAL = 16;
    private static final int LONGITUD_HASH = 32;
    private static final int PARALELISMO = 1;
    private static final int MEMORIA_KIB = 1 << 14; // 16 MB
    private static final int ITERACIONES = 2;
    private static final int UNIDADES_TOTALES = 4;  // 4 x 16 MB = 64 MB como máximo a la vez

    private static final Pattern PARAMETROS = Pattern.compile("\\$m=(\\d+),t=(\\d+),p=(\\d+)\\$");

    private final Argon2PasswordEncoder delegado =
            new Argon2PasswordEncoder(LONGITUD_SAL, LONGITUD_HASH, PARALELISMO, MEMORIA_KIB, ITERACIONES);
    private final Semaphore memoriaDisponible = new Semaphore(UNIDADES_TOTALES, true);

    @Override
    public String encode(CharSequence rawPassword) {
        memoriaDisponible.acquireUninterruptibly(1);
        try {
            return delegado.encode(rawPassword);
        } finally {
            memoriaDisponible.release(1);
        }
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        int unidades = unidadesPara(encodedPassword);
        memoriaDisponible.acquireUninterruptibly(unidades);
        try {
            return delegado.matches(rawPassword, encodedPassword);
        } finally {
            memoriaDisponible.release(unidades);
        }
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        Matcher parametros = encodedPassword == null ? null : PARAMETROS.matcher(encodedPassword);
        if (parametros == null || !parametros.find()) {
            return false;
        }
        return Integer.parseInt(parametros.group(1)) != MEMORIA_KIB
                || Integer.parseInt(parametros.group(2)) != ITERACIONES
                || Integer.parseInt(parametros.group(3)) != PARALELISMO;
    }

    private int unidadesPara(String encodedPassword) {
        Matcher parametros = encodedPassword == null ? null : PARAMETROS.matcher(encodedPassword);
        if (parametros == null || !parametros.find()) {
            return 1;
        }
        long memoria = Long.parseLong(parametros.group(1));
        long unidades = (memoria + MEMORIA_KIB - 1) / MEMORIA_KIB;
        return (int) Math.max(1, Math.min(UNIDADES_TOTALES, unidades));
    }
}
