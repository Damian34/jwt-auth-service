package com.example.security.auth.context.hashing.service;

import com.example.security.auth.context.hashing.properties.HashingProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class HashingPasswordService {
    private final HashingProperties hashingProperties;

    public String enrichWithHashing(String password, char[] salt) {
        String saltStr = String.valueOf(salt);
        return hashWithSha256(password + saltStr + hashingProperties.getPepper());
    }

    public char[] generateSalt() {
        return UUID.randomUUID().toString().toCharArray();
    }

    public boolean matches(String firstPassword, String secondPassword) {
        return Objects.equals(firstPassword, secondPassword);
    }

    private String hashWithSha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
