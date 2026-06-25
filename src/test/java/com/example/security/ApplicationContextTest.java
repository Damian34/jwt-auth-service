package com.example.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

@SpringBootTest
@ContextConfiguration(initializers = TestPostgresInitializer.class)
class ApplicationContextTest {

    @Test
    void contextTest() {
        // test context only
    }
}
