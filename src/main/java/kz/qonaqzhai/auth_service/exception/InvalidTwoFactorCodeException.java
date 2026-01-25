package kz.qonaqzhai.auth_service.exception;

public class InvalidTwoFactorCodeException extends RuntimeException {

    public InvalidTwoFactorCodeException() {
        super("INVALID_OTP");
    }
}
