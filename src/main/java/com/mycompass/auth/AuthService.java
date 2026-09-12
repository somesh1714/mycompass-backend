package com.mycompass.auth;

import com.mycompass.auth.dto.AuthResponse;
import com.mycompass.auth.dto.ForgotPasswordRequest;
import com.mycompass.auth.dto.GoogleLoginRequest;
import com.mycompass.auth.dto.LoginRequest;
import com.mycompass.auth.dto.RegisterRequest;
import com.mycompass.auth.dto.ResetPasswordRequest;
import com.mycompass.email.EmailService;
import com.mycompass.user.AuthProvider;
import com.mycompass.user.User;
import com.mycompass.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final long EMAIL_VERIFICATION_TTL_HOURS = 24;
    private static final long PASSWORD_RESET_TTL_HOURS = 1;
    private static final String FRONTEND_URL = "http://localhost:5173";

    private final UserRepository userRepository;
    private final VerificationTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final EmailService emailService;
    private final GoogleTokenVerifier googleTokenVerifier;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalStateException("Email already registered");
        }

        User user = User.builder()
                .email(request.email())
                .passwordHash(passwordEncoder.encode(request.password()))
                .name(request.name())
                .provider(AuthProvider.LOCAL)
                .emailVerified(false)
                .build();
        user = userRepository.save(user);

        issueEmailVerificationToken(user);

        String token = jwtService.generateToken(user.getId(), user.getEmail());
        return toAuthResponse(user, token);
    }

    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));

        if (user.getProvider() != AuthProvider.LOCAL || user.getPasswordHash() == null) {
            throw new IllegalArgumentException("This account signs in with Google, not a password");
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid email or password");
        }

        String token = jwtService.generateToken(user.getId(), user.getEmail());
        return toAuthResponse(user, token);
    }

    @Transactional
    public void verifyEmail(String rawToken) {
        VerificationToken verificationToken = tokenRepository
                .findByTokenAndType(rawToken, TokenType.EMAIL_VERIFICATION)
                .filter(VerificationToken::isValid)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired verification link"));

        verificationToken.getUser().setEmailVerified(true);
        verificationToken.setUsedAt(Instant.now());
    }

    @Transactional
    public void forgotPassword(ForgotPasswordRequest request) {
        // Always responds the same way to the caller regardless of the outcome here,
        // so the API never reveals whether an email address is registered.
        userRepository.findByEmail(request.email())
                .filter(user -> user.getProvider() == AuthProvider.LOCAL)
                .ifPresent(this::issuePasswordResetToken);
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        VerificationToken verificationToken = tokenRepository
                .findByTokenAndType(request.token(), TokenType.PASSWORD_RESET)
                .filter(VerificationToken::isValid)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired reset link"));

        verificationToken.getUser().setPasswordHash(passwordEncoder.encode(request.newPassword()));
        verificationToken.setUsedAt(Instant.now());
    }

    @Transactional
    public AuthResponse loginWithGoogle(GoogleLoginRequest request) {
        GoogleUserInfo googleUser = googleTokenVerifier.verify(request.idToken());

        User user = userRepository.findByEmail(googleUser.email())
                .map(existing -> linkGoogleIdIfNeeded(existing, googleUser.googleId()))
                .orElseGet(() -> createGoogleUser(googleUser));

        String token = jwtService.generateToken(user.getId(), user.getEmail());
        return toAuthResponse(user, token);
    }

    private User linkGoogleIdIfNeeded(User user, String googleId) {
        // An existing LOCAL account keeps its password AND gains Google as an
        // alternate sign-in method — provider is left as-is, only googleId is filled in.
        if (user.getGoogleId() == null) {
            user.setGoogleId(googleId);
        }
        return user;
    }

    private User createGoogleUser(GoogleUserInfo googleUser) {
        User user = User.builder()
                .email(googleUser.email())
                .name(googleUser.name())
                .provider(AuthProvider.GOOGLE)
                .googleId(googleUser.googleId())
                .emailVerified(true) // Google has already verified this email address
                .build();
        return userRepository.save(user);
    }

    private void issueEmailVerificationToken(User user) {
        VerificationToken verificationToken = VerificationToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .type(TokenType.EMAIL_VERIFICATION)
                .expiresAt(Instant.now().plus(EMAIL_VERIFICATION_TTL_HOURS, ChronoUnit.HOURS))
                .build();
        tokenRepository.save(verificationToken);

        String link = FRONTEND_URL + "/verify-email?token=" + verificationToken.getToken();
        emailService.send(user.getEmail(), "Verify your MyCompass email",
                "Welcome to MyCompass! Verify your email by visiting:\n" + link);
    }

    private void issuePasswordResetToken(User user) {
        VerificationToken verificationToken = VerificationToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .type(TokenType.PASSWORD_RESET)
                .expiresAt(Instant.now().plus(PASSWORD_RESET_TTL_HOURS, ChronoUnit.HOURS))
                .build();
        tokenRepository.save(verificationToken);

        String link = FRONTEND_URL + "/reset-password?token=" + verificationToken.getToken();
        emailService.send(user.getEmail(), "Reset your MyCompass password",
                "Reset your password by visiting:\n" + link
                        + "\n\nThis link expires in 1 hour. If you didn't request this, ignore this email.");
    }

    private AuthResponse toAuthResponse(User user, String token) {
        return new AuthResponse(token, user.getId(), user.getEmail(), user.getName(), user.isEmailVerified());
    }
}
