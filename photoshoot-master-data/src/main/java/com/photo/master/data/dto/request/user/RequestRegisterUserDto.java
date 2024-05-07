package com.photo.master.data.dto.request.user;

import com.photo.master.data.enumeration.Role;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RequestRegisterUserDto {
    private Long id;
    private RequestUserProfileDto userProfile;
    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Email is required")
    private String email;

    @NotBlank(message = "Password is required")
    private String password;
    private Role role;
    private boolean mfaEnabled;
}
