package PsykeP.AuthAPI.auth.services;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    // Obtiene el correo remitente desde application.properties (spring.mail.username)
    @Value("${spring.mail.username:no-reply@psykep.com}")
    private String remitente;

    public void enviarCodigoRecuperacion(String destinatario, String codigo) {
        try {
            SimpleMailMessage mensaje = new SimpleMailMessage();
            mensaje.setFrom(remitente);
            mensaje.setTo(destinatario);
            mensaje.setSubject("Código de Recuperación - PsykeP");
            mensaje.setText(
                "Hola,\n\n"
                + "Has solicitado restablecer tu contraseña en PsykeP.\n\n"
                + "Tu código de verificación es: " + codigo + "\n\n"
                + "Este código vencerá en 5 minutos.\n"
                + "Si no solicitaste este cambio, ignora este mensaje y tu cuenta permanecerá segura."
            );

            log.info("Enviando correo de recuperación a: {}", destinatario);
            mailSender.send(mensaje);
            log.info("Correo de recuperación enviado exitosamente a: {}", destinatario);

        } catch (MailException e) {
            log.error("Error al enviar el correo a {}: {}", destinatario, e.getMessage(), e);
            throw new RuntimeException("No se pudo enviar el correo de recuperación. Revisa la configuración del servidor SMTP.", e);
        }
    }
}
