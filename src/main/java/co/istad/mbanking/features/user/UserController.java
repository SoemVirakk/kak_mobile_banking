package co.istad.mbanking.features.user;

import co.istad.mbanking.base.BasedMessage;
import co.istad.mbanking.base.BasedResponse;
import co.istad.mbanking.features.user.dto.*;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping
    void createNew(@Valid @RequestBody UserCreateRequest userCreateRequest) {
        userService.createNew(userCreateRequest);
    }


    @PatchMapping("/{uuid}")
    UserResponse updateByUuid(@PathVariable String uuid,
                              @RequestBody UserUpdateRequest userUpdateRequest) {
        return userService.updateByUuid(uuid, userUpdateRequest);
    }

    @GetMapping
    Page<UserResponse> findList(
            @RequestParam(required = false, defaultValue = "0") int page,
            @RequestParam(required = false, defaultValue = "2") int limit) {
        return userService.findList(page, limit);
    }


    @GetMapping("/{uuid}")
    UserDetailsResponse findByUuid(@PathVariable String uuid) {
        return userService.findByUuid(uuid);
    }

    @PutMapping("/{uuid}/block")
    BasedMessage blockByUuid(@PathVariable String uuid) {
        return userService.blockByUuid(uuid);
    }

    // Delete user by UUID (hard delete) /{uuid}
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @DeleteMapping("/{uuid}")
    void deleteByUuid(@PathVariable String uuid) {
        userService.deleteByUuid(uuid);
    }

    // Disable user by UUID (soft delete) /{uuid}/disable

    // Enable user by UUID /{uuid}/enable

    // Update user profile image
    @PutMapping("/{uuid}/profile-image")
    BasedResponse<?> updateProfileImage(@PathVariable String uuid,
                                    @Valid @RequestBody UserProfileImageRequest userProfileImageRequest) {

        String newProfileImageUri = userService.updateProfileImage(uuid, userProfileImageRequest.mediaName());

        return BasedResponse.builder()
                .payload(newProfileImageUri)
                .build();
    }

}
