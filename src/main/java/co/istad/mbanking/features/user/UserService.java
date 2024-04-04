package co.istad.mbanking.features.user;

import co.istad.mbanking.base.BasedMessage;
import co.istad.mbanking.features.user.dto.UserCreateRequest;
import co.istad.mbanking.features.user.dto.UserDetailsResponse;
import co.istad.mbanking.features.user.dto.UserResponse;
import co.istad.mbanking.features.user.dto.UserUpdateRequest;
import org.springframework.data.domain.Page;

import java.util.List;

public interface UserService {

    void createNew(UserCreateRequest userCreateRequest);

    UserResponse updateByUuid(String uuid, UserUpdateRequest userUpdateRequest);

    Page<UserResponse> findList(int page, int limit);

    UserDetailsResponse findByUuid(String uuid);

    BasedMessage blockByUuid(String uuid);

    void deleteByUuid(String uuid);

    String updateProfileImage(String uuid, String mediaName);

}
