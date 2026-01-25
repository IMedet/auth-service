package kz.qonaqzhai.auth_service.service;

import kz.qonaqzhai.auth_service.dto.*;
import kz.qonaqzhai.auth_service.exception.InvalidTwoFactorCodeException;
import kz.qonaqzhai.auth_service.exception.TwoFactorRequiredException;
import kz.qonaqzhai.auth_service.model.Role;
import kz.qonaqzhai.auth_service.model.User;
import kz.qonaqzhai.auth_service.repository.UserRepository;
import kz.qonaqzhai.auth_service.util.JwtUtil;
import kz.qonaqzhai.auth_service.util.TotpUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final JwtUtil jwtUtil;

    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtil.generateJwtToken(authentication);

        User user = (User) authentication.getPrincipal();

        if (user.isTwoFactorEnabled()) {
            if (loginRequest.getOtp() == null || loginRequest.getOtp().isBlank()) {
                throw new TwoFactorRequiredException();
            }
            boolean ok = TotpUtil.verifyCode(user.getTwoFactorSecret(), loginRequest.getOtp());
            if (!ok) {
                throw new InvalidTwoFactorCodeException();
            }
        }

        List<String> roles = user.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return new JwtResponse(jwt,
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                roles);
    }

    public MessageResponse registerUser(SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new MessageResponse("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new MessageResponse("Error: Email is already in use!");
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null || strRoles.isEmpty()) {
            roles.add(Role.USER);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        roles.add(Role.ADMIN);
                        break;
                    case "mod":
                        roles.add(Role.MODERATOR);
                        break;
                    default:
                        roles.add(Role.USER);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return new MessageResponse("User registered successfully!");
    }

    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof User) {
            return (User) authentication.getPrincipal();
        }
        return null;
    }

    public UserProfileResponse getCurrentUserProfile() {
        User user = getCurrentUser();
        if (user == null) {
            return null;
        }

        return new UserProfileResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getFullName(),
                user.getPhone(),
                user.getCompany(),
                user.getLocation()
        );
    }

    public UserProfileResponse updateCurrentUserProfile(UpdateUserProfileRequest request) {
        User user = getCurrentUser();
        if (user == null) {
            return null;
        }

        if (request != null) {
            user.setFullName(request.getFullName());
            user.setPhone(request.getPhone());
            user.setCompany(request.getCompany());
            user.setLocation(request.getLocation());
        }

        User saved = userRepository.save(user);

        return new UserProfileResponse(
                saved.getId(),
                saved.getUsername(),
                saved.getEmail(),
                saved.getFullName(),
                saved.getPhone(),
                saved.getCompany(),
                saved.getLocation()
        );
    }

    public TwoFactorStatusResponse getTwoFactorStatus() {
        User user = getCurrentUser();
        if (user == null) {
            return null;
        }
        return new TwoFactorStatusResponse(user.isTwoFactorEnabled());
    }

    public TwoFactorSetupResponse setupTwoFactor() {
        User user = getCurrentUser();
        if (user == null) {
            return null;
        }

        String secret = TotpUtil.generateBase32Secret(20);
        user.setTwoFactorSecret(secret);
        user.setTwoFactorEnabled(false);
        userRepository.save(user);

        String issuer = "Qonaqzhai";
        String label = issuer + ":" + user.getUsername();
        String otpauthUri = "otpauth://totp/" + urlEncode(label)
                + "?secret=" + urlEncode(secret)
                + "&issuer=" + urlEncode(issuer)
                + "&algorithm=SHA1&digits=6&period=30";

        return new TwoFactorSetupResponse(secret, otpauthUri);
    }

    public TwoFactorStatusResponse enableTwoFactor(TwoFactorCodeRequest request) {
        User user = getCurrentUser();
        if (user == null) {
            return null;
        }

        if (user.getTwoFactorSecret() == null || user.getTwoFactorSecret().isBlank()) {
            // setup wasn't run yet
            throw new TwoFactorRequiredException();
        }

        boolean ok = TotpUtil.verifyCode(user.getTwoFactorSecret(), request != null ? request.getCode() : null);
        if (!ok) {
            throw new InvalidTwoFactorCodeException();
        }

        user.setTwoFactorEnabled(true);
        userRepository.save(user);
        return new TwoFactorStatusResponse(true);
    }

    public TwoFactorStatusResponse disableTwoFactor(TwoFactorCodeRequest request) {
        User user = getCurrentUser();
        if (user == null) {
            return null;
        }

        if (!user.isTwoFactorEnabled()) {
            return new TwoFactorStatusResponse(false);
        }

        boolean ok = TotpUtil.verifyCode(user.getTwoFactorSecret(), request != null ? request.getCode() : null);
        if (!ok) {
            throw new InvalidTwoFactorCodeException();
        }

        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        userRepository.save(user);
        return new TwoFactorStatusResponse(false);
    }

    private static String urlEncode(String value) {
        try {
            return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    public boolean validateToken(String token) {
        return jwtUtil.validateJwtToken(token);
    }

    public String getUsernameFromToken(String token) {
        return jwtUtil.getUserNameFromJwtToken(token);
    }
}
