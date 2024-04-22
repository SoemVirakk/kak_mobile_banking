package co.istad.mbanking.features.auth.dto;

public record AuthResponse(
        String type,
        String accessToken,
        String refreshToken
) {
}
