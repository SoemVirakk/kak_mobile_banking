package co.istad.mbanking.features.user.dto;

import jakarta.validation.constraints.NotBlank;

public record UserProfileImageRequest(
        @NotBlank(message = "Media is required")
        String mediaName
) {
}
