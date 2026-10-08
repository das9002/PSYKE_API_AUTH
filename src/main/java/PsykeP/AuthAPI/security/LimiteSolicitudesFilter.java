package PsykeP.AuthAPI.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Límite de peticiones (rate limiting) por IP. Cada ruta sensible tiene su propio límite
 * para frenar ataques de fuerza bruta (probar contraseñas o códigos) y el abuso del envío de correos.
 * Al superar el límite se responde 429 (Too Many Requests) con la cabecera Retry-After.
 */
public class LimiteSolicitudesFilter extends OncePerRequestFilter {

    private record Regla(String nombre, int maximo, long ventanaMs, boolean porSesion) {
        Regla(String nombre, int maximo, long ventanaMs) {
            this(nombre, maximo, ventanaMs, false);
        }
    }

    private static final String COOKIE_SESION = "psyke_auth_jwt";

    private static final long UN_MINUTO = 60_000;
    private static final long DIEZ_MINUTOS = 600_000;
    private static final int MAXIMO_REGISTROS = 10_000;

    private static final Map<String, Regla> REGLAS = Map.of(
            "/api/auth/login", new Regla("login", 10, UN_MINUTO),
            "/api/auth/register", new Regla("registro", 5, UN_MINUTO),
            "/api/auth/recuperar-contrasena", new Regla("recuperacion", 5, DIEZ_MINUTOS),
            "/api/auth/verificar-codigo", new Regla("verificacion", 10, DIEZ_MINUTOS),
            "/api/auth/restablecer-contrasena", new Regla("restablecer", 10, DIEZ_MINUTOS),
            "/api/auth/ws-ticket", new Regla("ticket-chat", 30, UN_MINUTO, true)
    );
    private static final Regla GENERAL = new Regla("general", 120, UN_MINUTO, true);

    private final Map<String, Ventana> ventanas = new ConcurrentHashMap<>();

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        return "OPTIONS".equalsIgnoreCase(request.getMethod());
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        Regla regla = REGLAS.getOrDefault(request.getRequestURI(), GENERAL);
        long ahora = System.currentTimeMillis();
        String clave = regla.nombre() + ":" + (regla.porSesion() ? identificarSesion(request) : identificarCliente(request));

        Ventana ventana = ventanas.compute(clave, (k, actual) ->
                actual == null || ahora - actual.inicio >= regla.ventanaMs() ? new Ventana(ahora, regla.ventanaMs()) : actual);

        if (ventana.conteo.incrementAndGet() > regla.maximo()) {
            long segundos = Math.max(1, (ventana.inicio + regla.ventanaMs() - ahora + 999) / 1000);
            responderLimiteExcedido(response, segundos);
            return;
        }

        limpiarVencidas(ahora);
        filterChain.doFilter(request, response);
    }

    /**
     * En el colegio muchos estudiantes salen a internet con la misma IP, así que las rutas
     * que se usan con la sesión iniciada se cuentan por sesión y no por IP.
     */
    private String identificarSesion(HttpServletRequest request) {
        String token = null;
        String cabecera = request.getHeader("Authorization");
        if (cabecera != null && cabecera.startsWith("Bearer ")) {
            token = cabecera.substring(7);
        } else if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (COOKIE_SESION.equals(cookie.getName())) {
                    token = cookie.getValue();
                    break;
                }
            }
        }
        if (token == null || token.isBlank()) {
            return identificarCliente(request);
        }
        return "sesion-" + Integer.toHexString(token.hashCode()) + "-" + token.length();
    }

    private String identificarCliente(HttpServletRequest request) {
        String reenviado = request.getHeader("X-Forwarded-For");
        if (reenviado != null && !reenviado.isBlank()) {
            return reenviado.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private void limpiarVencidas(long ahora) {
        if (ventanas.size() < MAXIMO_REGISTROS) return;
        ventanas.entrySet().removeIf(entrada -> ahora - entrada.getValue().inicio >= entrada.getValue().duracion);
    }

    private void responderLimiteExcedido(HttpServletResponse response, long segundos) throws IOException {
        response.setStatus(429);
        response.setHeader("Retry-After", String.valueOf(segundos));
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"status\":429,\"error\":\"Too Many Requests\",\"message\":"
                + "\"Demasiados intentos seguidos. Espera " + segundos + " segundos e intenta de nuevo.\","
                + "\"details\":{\"segundosRestantes\":\"" + segundos + "\"}}");
    }

    private static final class Ventana {
        private final long inicio;
        private final long duracion;
        private final AtomicInteger conteo = new AtomicInteger();

        private Ventana(long inicio, long duracion) {
            this.inicio = inicio;
            this.duracion = duracion;
        }
    }
}
