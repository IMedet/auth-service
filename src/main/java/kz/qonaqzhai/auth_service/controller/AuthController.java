package kz.qonaqzhai.auth_service.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import kz.qonaqzhai.auth_service.dto.*;
import kz.qonaqzhai.auth_service.model.User;
import kz.qonaqzhai.auth_service.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication and Authorization APIs")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signin")
    @Operation(summary = "Authenticate user and return JWT token")
    public ResponseEntity<JwtResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        JwtResponse jwtResponse = authService.authenticateUser(loginRequest);
        return ResponseEntity.ok(jwtResponse);
    }

    @PostMapping("/signup")
    @Operation(summary = "Register a new user")
    public ResponseEntity<MessageResponse> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        MessageResponse messageResponse = authService.registerUser(signUpRequest);
        
        if (messageResponse.getMessage().startsWith("Error")) {
            return ResponseEntity.badRequest().body(messageResponse);
        }
        
        return ResponseEntity.ok(messageResponse);
    }

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    @Operation(summary = "Get current user information")
    public ResponseEntity<UserMeResponse> getCurrentUser() {
        User currentUser = authService.getCurrentUser();
        if (currentUser == null) {
            return ResponseEntity.notFound().build();
        }

        List<String> roles = currentUser.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new UserMeResponse(
                currentUser.getId(),
                currentUser.getUsername(),
                currentUser.getEmail(),
                roles
        ));
    }

    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    @Operation(summary = "Get current user profile")
    public ResponseEntity<UserProfileResponse> getCurrentUserProfile() {
        UserProfileResponse profile = authService.getCurrentUserProfile();
        if (profile == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(profile);
    }

    @PutMapping("/profile")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    @Operation(summary = "Update current user profile")
    public ResponseEntity<UserProfileResponse> updateCurrentUserProfile(@RequestBody UpdateUserProfileRequest request) {
        UserProfileResponse profile = authService.updateCurrentUserProfile(request);
        if (profile == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(profile);
    }

    @GetMapping("/2fa/status")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    @Operation(summary = "Get current user 2FA status")
    public ResponseEntity<TwoFactorStatusResponse> getTwoFactorStatus() {
        TwoFactorStatusResponse status = authService.getTwoFactorStatus();
        if (status == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(status);
    }

    @PostMapping("/2fa/setup")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    @Operation(summary = "Generate 2FA secret and otpauth URI for current user")
    public ResponseEntity<TwoFactorSetupResponse> setupTwoFactor() {
        TwoFactorSetupResponse setup = authService.setupTwoFactor();
        if (setup == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(setup);
    }

    @PostMapping("/2fa/enable")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    @Operation(summary = "Enable 2FA for current user (requires valid TOTP code)")
    public ResponseEntity<TwoFactorStatusResponse> enableTwoFactor(@RequestBody TwoFactorCodeRequest request) {
        TwoFactorStatusResponse status = authService.enableTwoFactor(request);
        if (status == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(status);
    }

    @PostMapping("/2fa/disable")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    @Operation(summary = "Disable 2FA for current user (requires valid TOTP code)")
    public ResponseEntity<TwoFactorStatusResponse> disableTwoFactor(@RequestBody TwoFactorCodeRequest request) {
        TwoFactorStatusResponse status = authService.disableTwoFactor(request);
        if (status == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(status);
    }

    @PostMapping("/validate")
    @Operation(summary = "Validate JWT token")
    public ResponseEntity<MessageResponse> validateToken(@RequestParam String token) {
        boolean isValid = authService.validateToken(token);
        if (isValid) {
            String username = authService.getUsernameFromToken(token);
            return ResponseEntity.ok(new MessageResponse("Token is valid for user: " + username));
        }
        return ResponseEntity.badRequest().body(new MessageResponse("Invalid token"));
    }

    @GetMapping("/test/all")
    @Operation(summary = "Public content for all users")
    public ResponseEntity<String> allAccess() {
        return ResponseEntity.ok("Public Content.");
    }

    @GetMapping("/test/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    @Operation(summary = "Content for users with USER, MODERATOR or ADMIN role")
    public ResponseEntity<String> userAccess() {
        return ResponseEntity.ok("User Content.");
    }

    @GetMapping("/test/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    @Operation(summary = "Content for users with MODERATOR role")
    public ResponseEntity<String> moderatorAccess() {
        return ResponseEntity.ok("Moderator Board.");
    }

    @GetMapping("/test/admin")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Content for users with ADMIN role")
    public ResponseEntity<String> adminAccess() {
        return ResponseEntity.ok("Admin Board.");
    }


    @GetMapping("/test")
    @Operation(summary = "Test")
    public ResponseEntity<String> getTest(){
        return ResponseEntity.ok("Test");
    }

    @GetMapping("/testV2")
    public ResponseEntity<String> getTestV2(){
        return ResponseEntity.ok("TestV2");
    }
}
