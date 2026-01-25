package kz.qonaqzhai.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserMeResponse {

    private Long id;
    private String username;
    private String email;
    private List<String> roles;
}
