package com.mycompass.email;

public interface EmailService {

    void send(String to, String subject, String body);
}
