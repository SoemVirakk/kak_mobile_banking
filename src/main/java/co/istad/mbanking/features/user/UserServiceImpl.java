package co.istad.mbanking.features.user;

import co.istad.mbanking.base.BasedMessage;
import co.istad.mbanking.domain.Role;
import co.istad.mbanking.domain.User;
import co.istad.mbanking.features.user.dto.UserCreateRequest;
import co.istad.mbanking.features.user.dto.UserDetailsResponse;
import co.istad.mbanking.features.user.dto.UserResponse;
import co.istad.mbanking.features.user.dto.UserUpdateRequest;
import co.istad.mbanking.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;

    @Value("${media.base-uri}")
    private String mediaBaseUri;

    @Override
    public void createNew(UserCreateRequest userCreateRequest) {

        if (userRepository.existsByPhoneNumber(userCreateRequest.phoneNumber())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Phone number has already been existed!"
            );
        }

        if (userRepository.existsByNationalCardId(userCreateRequest.nationalCardId())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "National card ID has already been existed!"
            );
        }

        if (userRepository.existsByStudentIdCard(userCreateRequest.studentIdCard())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Student card ID has already been existed!"
            );
        }

        if (!userCreateRequest.password()
                .equals(userCreateRequest.confirmedPassword())) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Password doesn't match!"
            );
        }

        // DTO pattern (mapstruct ft. lombok)
        User user = userMapper.fromUserCreateRequest(userCreateRequest);
        user.setUuid(UUID.randomUUID().toString());
        user.setProfileImage("avatar.png");
        user.setCreatedAt(LocalDateTime.now());
        user.setIsBlocked(false);
        user.setIsDeleted(false);

        // Assign default user role
        List<Role> roles = new ArrayList<>();
        Role userRole = roleRepository.findByName("USER")
                        .orElseThrow(() ->
                                new ResponseStatusException(HttpStatus.NOT_FOUND,
                                        "Role USER has not been found!"));

        // Create dynamic role from client
        userCreateRequest.roles().forEach(r -> {
            Role newRole = roleRepository.findByName(r.name())
                    .orElseThrow(() ->
                            new ResponseStatusException(HttpStatus.NOT_FOUND,
                                    "Role USER has not been found!"));
            roles.add(newRole);
        });

        roles.add(userRole);
        user.setRoles(roles);

        userRepository.save(user);
    }

    @Override
    public UserResponse updateByUuid(String uuid, UserUpdateRequest userUpdateRequest) {

        // check uuid if exists
        User user = userRepository.findByUuid(uuid)
                .orElseThrow(() ->
                        new ResponseStatusException(HttpStatus.NOT_FOUND,
                                "User has not been found!"));

        log.info("before user: {}", user);

        userMapper.fromUserUpdateRequest(userUpdateRequest, user);


        user = userRepository.save(user);

        return userMapper.toUserResponse(user);
    }

    @Override
    public Page<UserResponse> findList(int page, int limit) {
        // Create pageRequest object
        PageRequest pageRequest = PageRequest.of(page, limit);
        // Invoke findAll(pageRequest)
        Page<User> users = userRepository.findAll(pageRequest);
        // Map result of pagination to response
        return users.map(userMapper::toUserResponse);
    }

    @Override
    public UserDetailsResponse findByUuid(String uuid) {

        User user = userRepository.findByUuid(uuid)
                .orElseThrow(() ->
                        new ResponseStatusException(HttpStatus.NOT_FOUND,
                                "User has not been found!"));

        return userMapper.toUserDetailsResponse(user);
    }

    @Transactional
    @Override
    public BasedMessage blockByUuid(String uuid) {

        if (!userRepository.existsByUuid(uuid)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "User has not been found!");
        }

        userRepository.blockByUuid(uuid);

        return new BasedMessage("User has been blocked");
    }

    @Override
    public void deleteByUuid(String uuid) {
        User user = userRepository.findByUuid(uuid)
                .orElseThrow(() ->
                        new ResponseStatusException(HttpStatus.NOT_FOUND,
                                "User has not been found!"));
        userRepository.delete(user);
    }

    @Override
    public String updateProfileImage(String uuid, String mediaName) {

        User user = userRepository.findByUuid(uuid)
                .orElseThrow(() ->
                        new ResponseStatusException(HttpStatus.NOT_FOUND,
                                "User has not been found!"));

        user.setProfileImage(mediaName);

        userRepository.save(user);

        return mediaBaseUri + "IMAGE/" + mediaName;
    }
}
