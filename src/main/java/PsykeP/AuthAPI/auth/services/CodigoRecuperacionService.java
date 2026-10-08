package PsykeP.AuthAPI.auth.services;

import PsykeP.AuthAPI.exceptions.RecuperacionException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CodigoRecuperacionService {

    private static final class Solicitud {
        private String codigoHash;
        private Instant expiraCodigo;
        private Instant reenvioDesde;
        private int intentosFallidos;
        private String tokenHash;
        private Instant expiraToken;
    }

    private final Map<String, Solicitud> solicitudes = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    private final Duration duracionCodigo;
    private final Duration esperaReenvio;
    private final Duration duracionToken;
    private final int maxIntentos;

    public CodigoRecuperacionService(
            @Value("${psyke.recuperacion.expiracion-minutos:10}") long minutosCodigo,
            @Value("${psyke.recuperacion.reenvio-segundos:30}") long segundosReenvio,
            @Value("${psyke.recuperacion.token-minutos:10}") long minutosToken,
            @Value("${psyke.recuperacion.max-intentos:5}") int maxIntentos) {
        this.duracionCodigo = Duration.ofMinutes(minutosCodigo);
        this.esperaReenvio = Duration.ofSeconds(segundosReenvio);
        this.duracionToken = Duration.ofMinutes(minutosToken);
        this.maxIntentos = maxIntentos;
    }

    public long getSegundosExpiracion() {
        return duracionCodigo.toSeconds();
    }

    public long getSegundosReenvio() {
        return esperaReenvio.toSeconds();
    }

    public String generarCodigo(String correo) {
        limpiarVencidas();
        String clave = normalizar(correo);
        Instant ahora = Instant.now();

        Solicitud anterior = solicitudes.get(clave);
        if (anterior != null && anterior.reenvioDesde != null && ahora.isBefore(anterior.reenvioDesde)) {
            long restantes = Math.max(1, Duration.between(ahora, anterior.reenvioDesde).toSeconds());
            throw new RecuperacionException(
                    HttpStatus.TOO_MANY_REQUESTS,
                    "Espera " + restantes + (restantes == 1 ? " segundo" : " segundos") + " antes de solicitar otro código.",
                    Map.of("segundosRestantes", String.valueOf(restantes))
            );
        }

        String codigo = String.format("%06d", random.nextInt(1_000_000));

        Solicitud solicitud = new Solicitud();
        solicitud.codigoHash = hash(codigo);
        solicitud.expiraCodigo = ahora.plus(duracionCodigo);
        solicitud.reenvioDesde = ahora.plus(esperaReenvio);
        solicitudes.put(clave, solicitud);

        return codigo;
    }

    public void descartar(String correo) {
        solicitudes.remove(normalizar(correo));
    }

    public String verificarCodigo(String correo, String codigo) {
        String clave = normalizar(correo);
        Solicitud solicitud = solicitudes.get(clave);
        Instant ahora = Instant.now();

        if (solicitud == null || solicitud.codigoHash == null || ahora.isAfter(solicitud.expiraCodigo)) {
            throw new RecuperacionException(HttpStatus.BAD_REQUEST, "El código expiró o no es válido. Solicita uno nuevo.");
        }

        synchronized (solicitud) {
            if (solicitud.intentosFallidos >= maxIntentos) {
                solicitudes.remove(clave);
                throw new RecuperacionException(HttpStatus.TOO_MANY_REQUESTS, "Superaste el número de intentos. Solicita un nuevo código.");
            }

            if (!coincide(hash(codigo), solicitud.codigoHash)) {
                solicitud.intentosFallidos++;
                int restantes = maxIntentos - solicitud.intentosFallidos;
                if (restantes <= 0) {
                    solicitudes.remove(clave);
                    throw new RecuperacionException(HttpStatus.TOO_MANY_REQUESTS, "Superaste el número de intentos. Solicita un nuevo código.");
                }
                throw new RecuperacionException(
                        HttpStatus.BAD_REQUEST,
                        "Código incorrecto. Te quedan " + restantes + (restantes == 1 ? " intento." : " intentos."),
                        Map.of("intentosRestantes", String.valueOf(restantes))
                );
            }

            byte[] bytes = new byte[32];
            random.nextBytes(bytes);
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

            solicitud.codigoHash = null;
            solicitud.tokenHash = hash(token);
            solicitud.expiraToken = ahora.plus(duracionToken);
            return token;
        }
    }

    public long getSegundosToken() {
        return duracionToken.toSeconds();
    }

    public void validarToken(String correo, String token) {
        Solicitud solicitud = solicitudes.get(normalizar(correo));
        if (solicitud == null || solicitud.tokenHash == null
                || Instant.now().isAfter(solicitud.expiraToken)
                || !coincide(hash(token), solicitud.tokenHash)) {
            throw new RecuperacionException(HttpStatus.BAD_REQUEST, "La autorización expiró. Vuelve a solicitar un código.");
        }
    }

    public void consumirToken(String correo) {
        solicitudes.remove(normalizar(correo));
    }

    private void limpiarVencidas() {
        Instant ahora = Instant.now();
        solicitudes.entrySet().removeIf(e -> {
            Solicitud s = e.getValue();
            boolean codigoVencido = s.codigoHash == null || ahora.isAfter(s.expiraCodigo);
            boolean tokenVencido = s.tokenHash == null || ahora.isAfter(s.expiraToken);
            boolean reenvioLibre = s.reenvioDesde == null || ahora.isAfter(s.reenvioDesde);
            return codigoVencido && tokenVencido && reenvioLibre;
        });
    }

    private static String normalizar(String correo) {
        return correo == null ? "" : correo.trim().toLowerCase(Locale.ROOT);
    }

    private static boolean coincide(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static String hash(String valor) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(valor.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
