package com.example.security.auth;

import com.example.security.TestPostgresInitializer;
import com.example.security.TestUserHelper;
import com.example.security.auth.api.protocol.request.RefreshTokenRequest;
import com.example.security.auth.api.protocol.response.RefreshTokenResponse;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assertions;
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
class AuthControllerRefreshTokenTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private TestUserHelper helper;

    @BeforeEach
    void setup() {
        helper.cleanUsers();
    }

    @Test
    void shouldRefreshTokenSuccessfullyTest() throws Exception {
        // given
        var loginResponse = helper.registerAndLoginUser("testUsername", "strong password");
        var refreshTokenRequest = new RefreshTokenRequest(loginResponse.getRefreshToken());
        Thread.sleep(1000);

        // when
        var response = mockMvc.perform(post("/api/auth/refresh-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(refreshTokenRequest)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        var refreshTokenResponse = mapper.readValue(response, RefreshTokenResponse.class);

        // then
        Assertions.assertNotEquals(loginResponse.getRefreshToken(), refreshTokenResponse.getRefreshToken());
        Assertions.assertNotEquals(loginResponse.getAccessToken(), refreshTokenResponse.getAccessToken());
    }

    @Test
    void shouldRefreshTokenFailWhenTheSendInvalidTokenTest() throws Exception {
        // given
        String testToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0VXNlcm5hbWUiLCJpYXQiOjE3MzgwMTEwNjEsImV4cCI6MTczODAxMjg2MX0.onCxznBkowagmCY5W8GYYnc90Jh9N-JJhiCAm0wF9J0";
        var refreshTokenRequest = new RefreshTokenRequest(testToken);

        // when and then
        mockMvc.perform(post("/api/auth/refresh-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(refreshTokenRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error")
                        .value("Invalid refresh refreshToken."));
    }

}
