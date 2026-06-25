package com.example.security.auth.context.user.service;

import com.example.security.auth.api.protocol.request.RegistryRequest;
import com.example.security.auth.context.hashing.service.HashingPasswordService;
import com.example.security.auth.context.user.validator.UserValidator;
import com.example.security.shared.model.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserRegistryService {
    private final UserAuthService userAuthService;
    private final UserValidator userValidator;
    private final HashingPasswordService hashingService;

    public String registerUser(RegistryRequest request) {
        userValidator.validateUsername(request.username());
        User user = new User();
        char[] salt = hashingService.generateSalt();
        String enrichedPassword = hashingService.enrichWithHashing(request.password(), salt);
        user.setUsername(request.username());
        user.setPassword(enrichedPassword);
        user.setSalt(salt);
        user.setRoles(Set.of(userAuthService.getRoleUser()));
        userAuthService.save(user);
        return "User registered successfully!";
    }
}
