package co.istad.mbanking.features.user;

import co.istad.mbanking.domain.Role;
import co.istad.mbanking.domain.User;
import co.istad.mbanking.features.user.dto.UserCreateRequest;
import co.istad.mbanking.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;

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
        roles.add(userRole);
        user.setRoles(roles);

        userRepository.save(user);
    }
}
