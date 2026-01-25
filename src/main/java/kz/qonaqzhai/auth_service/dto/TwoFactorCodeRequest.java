package kz.qonaqzhai.auth_service.dto;

import lombok.Data;

@Data
public class TwoFactorCodeRequest {

    private String code;
}
