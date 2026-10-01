package PsykeP.AuthAPI.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    public void enviarCodigoRecuperacion(String destinatario, String codigo) {
        SimpleMailMessage mensaje = new SimpleMailMessage();
        mensaje.setTo(destinatario);
        mensaje.setSubject("Código de Recuperación - PsykeP");
        mensaje.setText("Hola,\n\n"
            + "Has solicitado restablecer tu contraseña.\n"
            + "Tu código de verificación es: " + codigo + "\n\n"
            + "Este código vencerá en 5 minutos.\n"
            + "Si no solicitaste este cambio, ignora este mensaje.");

        mailSender.send(mensaje);
    }
}