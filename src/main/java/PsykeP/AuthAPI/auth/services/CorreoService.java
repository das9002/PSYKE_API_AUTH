package PsykeP.AuthAPI.auth.services;

import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

@Service
@RequiredArgsConstructor
public class CorreoService {

    private static final Logger log = LoggerFactory.getLogger(CorreoService.class);

    private final JavaMailSender mailSender;

    @Value("${psyke.mail.remitente:${spring.mail.username:}}")
    private String remitente;

    @Value("${psyke.mail.nombre-remitente:Psyke}")
    private String nombreRemitente;

    public boolean enviarCodigoRecuperacion(String destinatario, String codigo, long minutosVigencia) {
        if (remitente == null || remitente.isBlank()) {
            log.error("No hay remitente configurado (MAIL_USERNAME). No se puede enviar el correo de recuperación.");
            return false;
        }

        try {
            MimeMessage mensaje = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mensaje, true, StandardCharsets.UTF_8.name());
            helper.setFrom(remitente, nombreRemitente);
            helper.setTo(destinatario);
            helper.setSubject("Psyke - Código para restablecer tu contraseña");
            helper.setText(textoPlano(codigo, minutosVigencia), plantillaHtml(codigo, minutosVigencia));
            mailSender.send(mensaje);
            return true;
        } catch (Exception ex) {
            log.error("Error al enviar el correo de recuperación a {}", destinatario, ex);
            return false;
        }
    }

    private String textoPlano(String codigo, long minutos) {
        return "Hola,\n\n"
                + "Recibimos una solicitud para restablecer la contraseña de tu cuenta de Psyke.\n\n"
                + "Tu código de verificación es: " + codigo + "\n\n"
                + "El código vence en " + minutos + " minutos. Si no solicitaste este cambio, ignora este correo; tu contraseña seguirá igual.\n\n"
                + "Equipo Psyke";
    }

    private String plantillaHtml(String codigo, long minutos) {
        return """
                <!DOCTYPE html>
                <html lang="es">
                <body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;">
                  <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:32px 12px;">
                    <tr>
                      <td align="center">
                        <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;">
                          <tr>
                            <td style="background:#2F6DF6;padding:22px 28px;color:#ffffff;font-size:22px;font-weight:bold;">Psyke</td>
                          </tr>
                          <tr>
                            <td style="padding:28px;color:#0f172a;">
                              <p style="margin:0 0 12px;font-size:18px;font-weight:bold;">Restablecer contraseña</p>
                              <p style="margin:0 0 20px;font-size:14px;color:#475569;line-height:1.5;">
                                Recibimos una solicitud para restablecer la contraseña de tu cuenta. Ingresa este código en la pantalla de recuperación:
                              </p>
                              <p style="margin:0 0 20px;text-align:center;">
                                <span style="display:inline-block;padding:14px 22px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:12px;font-size:32px;letter-spacing:8px;font-weight:bold;color:#1d4ed8;">%s</span>
                              </p>
                              <p style="margin:0 0 8px;font-size:13px;color:#475569;">El código vence en <strong>%d minutos</strong> y solo puede usarse una vez.</p>
                              <p style="margin:0;font-size:13px;color:#475569;">Si no solicitaste este cambio, ignora este correo; tu contraseña seguirá igual.</p>
                            </td>
                          </tr>
                          <tr>
                            <td style="padding:16px 28px;background:#f8fafc;font-size:12px;color:#94a3b8;">
                              Sistema de Psicología de Gestión Estudiantil · Instituto Técnico Ricaldone
                            </td>
                          </tr>
                        </table>
                      </td>
                    </tr>
                  </table>
                </body>
                </html>
                """.formatted(codigo, minutos);
    }
}
