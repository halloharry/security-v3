package com.photo.master.data.dto.request.user;

import com.photo.master.data.model.user.AuthUser;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.time.LocalDate;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RequestUserProfileDto {
    private Long id;
    private String firstName;
    private String lastName;
    @NotBlank(message = "phone number is required")
    private String phoneNumber;
    private String address;
    private LocalDate birtDate;
    private String gender;
}
