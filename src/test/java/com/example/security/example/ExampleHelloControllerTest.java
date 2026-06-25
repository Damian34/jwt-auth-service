package com.example.security.example;

import com.example.security.TestPostgresInitializer;
import com.example.security.TestUserHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@SpringBootTest
@ContextConfiguration(initializers = TestPostgresInitializer.class)
class ExampleHelloControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TestUserHelper helper;

    @BeforeEach
    void setup() {
        helper.cleanUsers();
    }

    @Test
    void shouldLoginAndGetMessageTest() throws Exception {
        // given
        String username = "testUsername";
        var loginResponse = helper.registerAndLoginUser(username, "strong password");

        // when and then
        mockMvc.perform(get("/api/hello")
                        .header("Authorization", "Bearer " + loginResponse.getAccessToken()))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello " + username));
    }

    @Test
    void shouldFailWhenIncorrectAccessTokenTest() throws Exception {
        // given
        String invalidAccessToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0VYNlcm5hbWUiLCJpYXQiOjE3MzgwMTEwNjEsImV4cCI6MTczODAxMjg2MX0.onCxznBkowagmCY5W8GYYnc90Jh9N-JJhiCAm0wF1J0";

        // when and then
        mockMvc.perform(get("/api/hello")
                .header("Authorization", "Bearer " + invalidAccessToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error")
                        .value("Invalid JWT token"));
    }
}
