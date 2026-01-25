package kz.qonaqzhai.auth_service.dto;

import lombok.Data;

@Data
public class UpdateUserProfileRequest {

    private String fullName;
    private String phone;
    private String company;
    private String location;
}
