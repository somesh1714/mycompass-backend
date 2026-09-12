package com.mycompass.email;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Logs emails to the console instead of actually sending them.
 * No SMTP provider is wired up yet — swap this out for a real
 * {@link EmailService} implementation (e.g. JavaMailSender) once one is chosen,
 * without touching any of the auth flow that calls this interface.
 */
@Slf4j
@Service
public class ConsoleEmailService implements EmailService {

    @Override
    public void send(String to, String subject, String body) {
        log.info("""

                ==================== EMAIL (dev mode) ====================
                To:      {}
                Subject: {}
                ------------------------------------------------------------
                {}
                ============================================================
                """, to, subject, body);
    }
}
