package com.example.security.auth;

import com.example.security.TestPostgresInitializer;
import com.example.security.TestUserHelper;
import com.example.security.auth.api.protocol.request.LoginRequest;
import com.example.security.auth.context.jwt.properties.JwtProperties;
import com.example.security.auth.context.refreshtoken.properties.RefreshTokenProperties;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@SpringBootTest
@ContextConfiguration(initializers = TestPostgresInitializer.class)
class AuthControllerLoginTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private TestUserHelper helper;

    @Autowired
    private JwtProperties jwtProperties;

    @Autowired
    private RefreshTokenProperties refreshTokenProperties;

    @BeforeEach
    void setup() {
        helper.cleanUsers();
    }

    @Test
    void shouldLoginSuccessfullyTest() throws Exception {
        // given
        var request = new LoginRequest("testUsername", "strong password");
        helper.registerUser(request.username(), request.password());

        // when and then
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.username").value(request.username()))
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.roles").isNotEmpty())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.accessTokenExpiresIn").value(jwtProperties.getExpirationTime()))
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.refreshTokenExpiresIn").value(refreshTokenProperties.getExpirationTime()));
    }

    @Test
    void shouldLoginWhenUsernameNoExistsTest() throws Exception {
        // given
        var request = new LoginRequest("testUsername", "strong password");
        helper.registerUser("not_" + request.username(), request.password());

        // when and then
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error")
                        .value("Invalid username or password"));
    }

    @Test
    void shouldLoginWhenIncorrectPasswordTest() throws Exception {
        // given
        var request = new LoginRequest("testUsername", "strong password");
        helper.registerUser(request.username(), "other " + request.password());

        // when and then
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error")
                        .value("Invalid username or password"));
    }
}
