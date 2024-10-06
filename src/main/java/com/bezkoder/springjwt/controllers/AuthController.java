package com.bezkoder.springjwt.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.bezkoder.springjwt.models.*;
import com.bezkoder.springjwt.payload.request.ForgotPasswordRequest;
import com.bezkoder.springjwt.payload.request.ResetPasswordRequest;
import com.bezkoder.springjwt.repository.ConfirmationTokenRepository;
import com.bezkoder.springjwt.repository.PasswordResetTokenRepository;
import com.bezkoder.springjwt.services.EmailService;
import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.bezkoder.springjwt.payload.request.LoginRequest;
import com.bezkoder.springjwt.payload.request.SignupRequest;
import com.bezkoder.springjwt.payload.response.JwtResponse;
import com.bezkoder.springjwt.payload.response.MessageResponse;
import com.bezkoder.springjwt.repository.RoleRepository;
import com.bezkoder.springjwt.repository.UserRepository;
import com.bezkoder.springjwt.security.jwt.JwtUtils;
import com.bezkoder.springjwt.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  private EmailService emailService;

  @Autowired
  ConfirmationTokenRepository confirmationTokenRepository;

  @Autowired
  PasswordResetTokenRepository passwordResetTokenRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);
    
    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();    
    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());

    return ResponseEntity.ok(new JwtResponse(jwt, 
                         userDetails.getId(), 
                         userDetails.getUsername(), 
                         userDetails.getEmail(), 
                         roles));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
    }

    // Cria a conta do usuário
    User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(), encoder.encode(signUpRequest.getPassword()));
    user.setEnabled(false);  // Não habilitado até a confirmação por e-mail

    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
          case "admin":
            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(adminRole);
            break;
          case "mod":
            Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(modRole);
            break;
          default:
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        }
      });
    }

    user.setRoles(roles);
    userRepository.save(user);

    // Gera um token de confirmação
    String token = UUID.randomUUID().toString();

    ConfirmationToken confirmationToken = new ConfirmationToken(token, user);
    confirmationTokenRepository.save(confirmationToken);

    // Enviar email de confirmação
    String confirmationUrl = "http://localhost:8080/api/auth/confirm?token=" + token;
    emailService.sendConfirmationEmail(user.getEmail(), "Confirme sua conta", "Clique no link para confirmar: " + confirmationUrl);

    return ResponseEntity.ok(new MessageResponse("Usuário registrado! Por favor, verifique seu email para confirmar sua conta."));
  }

  @GetMapping("/confirm")
  public ResponseEntity<?> confirmUser(@RequestParam("token") String token) {
    com.bezkoder.springjwt.models.ConfirmationToken confirmationToken = confirmationTokenRepository.findByToken(token)
            .orElseThrow(() -> new RuntimeException("Token inválido ou expirado"));

    User user = confirmationToken.getUser();
    user.setEnabled(true);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("Conta confirmada com sucesso!"));
  }

  @PostMapping("/forgot-password")
  public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
    User user = userRepository.findByEmail(request.getEmail())
            .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

    // Gera um token de recuperação de senha
    String token = UUID.randomUUID().toString();
    PasswordResetToken passwordResetToken = new PasswordResetToken(token, user);
    passwordResetTokenRepository.save(passwordResetToken);

    // Envia email com o link de reset
    String resetUrl = "http://localhost:8080/api/auth/reset-password?token=" + token;
    emailService.sendConfirmationEmail(user.getEmail(), "Redefina sua senha", "Clique no link para redefinir sua senha: " + resetUrl);

    return ResponseEntity.ok(new MessageResponse("Solicitação de redefinição de senha enviada! Verifique seu e-mail."));
  }

  @PutMapping("/reset-password")
  public ResponseEntity<?> resetPassword(@RequestParam("token") String token, @RequestBody ResetPasswordRequest request) {
    PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token)
            .orElseThrow(() -> new RuntimeException("Token inválido ou expirado"));

    User user = resetToken.getUser();
    user.setPassword(encoder.encode(request.getPassword()));
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("Senha alterada com sucesso!"));
  }
}


