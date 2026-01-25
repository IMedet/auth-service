package kz.qonaqzhai.auth_service.exception;

public class TwoFactorRequiredException extends RuntimeException {

    public TwoFactorRequiredException() {
        super("2FA_REQUIRED");
    }
}
