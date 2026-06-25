package com.example.security.auth.context.jwt.service;

import com.example.security.auth.context.authorization.service.AuthorizationService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenService jwtTokenService;
    private final UserDetailsService userDetailsService;
    private final AuthorizationService authorizationService;
    private final ObjectMapper mapper;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if (authorizationService.isPermittedPath(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");
        String bearer = "Bearer ";

        if (authHeader == null || !authHeader.startsWith(bearer)) {
            filterChain.doFilter(request, response);
            appendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Authorization header is missing", null);
            return;
        }

        try {
            String jwt = authHeader.substring(bearer.length());
            String username = jwtTokenService.extractUsername(jwt);
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (username != null && authentication == null) {
                var authToken = createAuthToken(jwt, username, request);
                if (authToken != null) {
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                } else {
                    appendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Expired JWT token", null);
                    return;
                }
            }

            filterChain.doFilter(request, response);
        } catch (JwtException e) {
            appendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token", e);
        } catch (Exception e) {
            appendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal server error", e);
        }
    }

    private UsernamePasswordAuthenticationToken createAuthToken(String jwt, String username, HttpServletRequest request) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (jwtTokenService.isTokenValid(jwt, userDetails)) {
            var authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            return authToken;
        }
        return null;
    }

    private void appendErrorResponse(HttpServletResponse response, int status, String message, Exception e) throws IOException {
        String logMessage = message;
        if (e != null) {
            logMessage += ": " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        log.warn("Authorization exception with status {}: {}", status, logMessage);
        response.setStatus(status);
        response.setContentType("application/json");
        var errorResponse = Map.of("error", message);
        response.getWriter().write(mapper.writeValueAsString(errorResponse));
    }
}
