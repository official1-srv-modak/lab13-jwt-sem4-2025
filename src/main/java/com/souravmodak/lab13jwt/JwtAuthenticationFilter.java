package com.souravmodak.lab13jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private final JwtHelperService jwtAuthenticationService;
    public JwtAuthenticationFilter(JwtHelperService jwtAuthenticationService) {
        this.jwtAuthenticationService = jwtAuthenticationService;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            try {
                Optional<User> balkanDateUserOptional = Optional.ofNullable(jwtAuthenticationService.validateToken(token));
                balkanDateUserOptional.ifPresent(balkanDateUser -> {
                    String username = balkanDateUser.getUsername();
                    String password = balkanDateUser.getPassword();
                    String role = balkanDateUser.getRole();

                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(
                                    username,
                                    password,
                                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role))
                            );

                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                });

            } catch (Exception e) {
                response.setContentType("application/json");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

                // Write response body
                response.getWriter().write("{\"error\": \"Invalid JWT Token\", \"message\": \"" + e.getMessage() + "\"}");
                response.getWriter().flush();
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
