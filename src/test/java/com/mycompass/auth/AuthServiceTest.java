package com.mycompass.auth;

import com.mycompass.auth.dto.AuthResponse;
import com.mycompass.auth.dto.ForgotPasswordRequest;
import com.mycompass.auth.dto.LoginRequest;
import com.mycompass.auth.dto.RegisterRequest;
import com.mycompass.auth.dto.ResetPasswordRequest;
import com.mycompass.email.EmailService;
import com.mycompass.user.AuthProvider;
import com.mycompass.user.User;
import com.mycompass.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the core auth business rules — register, login, email
 * verification, and password reset. All collaborators are mocked; no
 * database or Spring context is involved, so these run fast and exercise
 * exactly the logic AuthService itself is responsible for.
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private VerificationTokenRepository tokenRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtService jwtService;
    @Mock
    private EmailService emailService;

    @InjectMocks
    private AuthService authService;

    private User existingUser;

    @BeforeEach
    void setUp() {
        existingUser = User.builder()
                .id(UUID.randomUUID())
                .email("somesh@example.com")
                .passwordHash("hashed-password")
                .name("Somesh")
                .provider(AuthProvider.LOCAL)
                .emailVerified(false)
                .build();
    }

    // ---------- register ----------

    @Test
    void register_createsUser_issuesVerificationToken_andReturnsJwt() {
        RegisterRequest request = new RegisterRequest("new@example.com", "Passw0rd!", "New User");

        when(userRepository.existsByEmail(request.email())).thenReturn(false);
        when(passwordEncoder.encode(request.password())).thenReturn("hashed");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User u = invocation.getArgument(0);
            u.setId(UUID.randomUUID());
            return u;
        });
        when(jwtService.generateToken(any(UUID.class), eq(request.email()))).thenReturn("jwt-token");

        AuthResponse response = authService.register(request);

        assertThat(response.token()).isEqualTo("jwt-token");
        assertThat(response.email()).isEqualTo(request.email());
        assertThat(response.emailVerified()).isFalse();

        verify(tokenRepository).save(argThat(token ->
                token.getType() == TokenType.EMAIL_VERIFICATION && token.isValid()));
        verify(emailService).send(eq(request.email()), contains("Verify"), contains("verify-email?token="));
    }

    @Test
    void register_rejectsDuplicateEmail() {
        RegisterRequest request = new RegisterRequest(existingUser.getEmail(), "Passw0rd!", "Dup");
        when(userRepository.existsByEmail(existingUser.getEmail())).thenReturn(true);

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("already registered");

        verifyNoInteractions(tokenRepository, emailService, jwtService);
    }

    // ---------- login ----------

    @Test
    void login_succeedsWithCorrectPassword() {
        LoginRequest request = new LoginRequest(existingUser.getEmail(), "Passw0rd!");
        when(userRepository.findByEmail(existingUser.getEmail())).thenReturn(Optional.of(existingUser));
        when(passwordEncoder.matches(request.password(), existingUser.getPasswordHash())).thenReturn(true);
        when(jwtService.generateToken(existingUser.getId(), existingUser.getEmail())).thenReturn("jwt-token");

        AuthResponse response = authService.login(request);

        assertThat(response.token()).isEqualTo("jwt-token");
        assertThat(response.userId()).isEqualTo(existingUser.getId());
    }

    @Test
    void login_rejectsWrongPassword() {
        LoginRequest request = new LoginRequest(existingUser.getEmail(), "WrongPassword");
        when(userRepository.findByEmail(existingUser.getEmail())).thenReturn(Optional.of(existingUser));
        when(passwordEncoder.matches(request.password(), existingUser.getPasswordHash())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid email or password");

        verify(jwtService, never()).generateToken(any(), any());
    }

    @Test
    void login_rejectsUnknownEmail() {
        LoginRequest request = new LoginRequest("nobody@example.com", "whatever");
        when(userRepository.findByEmail(request.email())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void login_rejectsGoogleOnlyAccount() {
        User googleUser = User.builder()
                .id(UUID.randomUUID())
                .email("google@example.com")
                .passwordHash(null)
                .name("Google User")
                .provider(AuthProvider.GOOGLE)
                .emailVerified(true)
                .build();
        LoginRequest request = new LoginRequest(googleUser.getEmail(), "anything");
        when(userRepository.findByEmail(googleUser.getEmail())).thenReturn(Optional.of(googleUser));

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Google");

        verifyNoInteractions(passwordEncoder);
    }

    // ---------- verifyEmail ----------

    @Test
    void verifyEmail_marksUserVerifiedAndTokenUsed() {
        VerificationToken token = VerificationToken.builder()
                .token("abc123")
                .user(existingUser)
                .type(TokenType.EMAIL_VERIFICATION)
                .expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
                .build();
        when(tokenRepository.findByTokenAndType("abc123", TokenType.EMAIL_VERIFICATION))
                .thenReturn(Optional.of(token));

        authService.verifyEmail("abc123");

        assertThat(existingUser.isEmailVerified()).isTrue();
        assertThat(token.getUsedAt()).isNotNull();
    }

    @Test
    void verifyEmail_rejectsExpiredToken() {
        VerificationToken expired = VerificationToken.builder()
                .token("expired-token")
                .user(existingUser)
                .type(TokenType.EMAIL_VERIFICATION)
                .expiresAt(Instant.now().minus(1, ChronoUnit.HOURS))
                .build();
        when(tokenRepository.findByTokenAndType("expired-token", TokenType.EMAIL_VERIFICATION))
                .thenReturn(Optional.of(expired));

        assertThatThrownBy(() -> authService.verifyEmail("expired-token"))
                .isInstanceOf(IllegalArgumentException.class);

        assertThat(existingUser.isEmailVerified()).isFalse();
    }

    @Test
    void verifyEmail_rejectsAlreadyUsedToken() {
        VerificationToken used = VerificationToken.builder()
                .token("used-token")
                .user(existingUser)
                .type(TokenType.EMAIL_VERIFICATION)
                .expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
                .usedAt(Instant.now().minus(1, ChronoUnit.MINUTES))
                .build();
        when(tokenRepository.findByTokenAndType("used-token", TokenType.EMAIL_VERIFICATION))
                .thenReturn(Optional.of(used));

        assertThatThrownBy(() -> authService.verifyEmail("used-token"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void verifyEmail_rejectsUnknownToken() {
        when(tokenRepository.findByTokenAndType("nope", TokenType.EMAIL_VERIFICATION))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.verifyEmail("nope"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ---------- forgotPassword ----------

    @Test
    void forgotPassword_issuesResetTokenForLocalUser() {
        ForgotPasswordRequest request = new ForgotPasswordRequest(existingUser.getEmail());
        when(userRepository.findByEmail(existingUser.getEmail())).thenReturn(Optional.of(existingUser));

        authService.forgotPassword(request);

        verify(tokenRepository).save(argThat(t -> t.getType() == TokenType.PASSWORD_RESET));
        verify(emailService).send(eq(existingUser.getEmail()), contains("Reset"), contains("reset-password?token="));
    }

    @Test
    void forgotPassword_doesNothingForUnknownEmail() {
        ForgotPasswordRequest request = new ForgotPasswordRequest("nobody@example.com");
        when(userRepository.findByEmail(request.email())).thenReturn(Optional.empty());

        authService.forgotPassword(request);

        verifyNoInteractions(tokenRepository, emailService);
    }

    @Test
    void forgotPassword_doesNothingForGoogleOnlyAccount() {
        User googleUser = User.builder()
                .id(UUID.randomUUID())
                .email("google@example.com")
                .provider(AuthProvider.GOOGLE)
                .build();
        ForgotPasswordRequest request = new ForgotPasswordRequest(googleUser.getEmail());
        when(userRepository.findByEmail(googleUser.getEmail())).thenReturn(Optional.of(googleUser));

        authService.forgotPassword(request);

        verifyNoInteractions(tokenRepository, emailService);
    }

    // ---------- resetPassword ----------

    @Test
    void resetPassword_updatesPasswordAndMarksTokenUsed() {
        VerificationToken token = VerificationToken.builder()
                .token("reset-token")
                .user(existingUser)
                .type(TokenType.PASSWORD_RESET)
                .expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
                .build();
        ResetPasswordRequest request = new ResetPasswordRequest("reset-token", "NewPassw0rd!");
        when(tokenRepository.findByTokenAndType("reset-token", TokenType.PASSWORD_RESET))
                .thenReturn(Optional.of(token));
        when(passwordEncoder.encode("NewPassw0rd!")).thenReturn("new-hashed");

        authService.resetPassword(request);

        assertThat(existingUser.getPasswordHash()).isEqualTo("new-hashed");
        assertThat(token.getUsedAt()).isNotNull();
    }

    @Test
    void resetPassword_rejectsExpiredOrUnknownToken() {
        ResetPasswordRequest request = new ResetPasswordRequest("bad-token", "NewPassw0rd!");
        when(tokenRepository.findByTokenAndType("bad-token", TokenType.PASSWORD_RESET))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.resetPassword(request))
                .isInstanceOf(IllegalArgumentException.class);

        verifyNoInteractions(passwordEncoder);
    }
}
