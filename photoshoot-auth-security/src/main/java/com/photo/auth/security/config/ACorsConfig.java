package com.photo.auth.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;
import java.util.Objects;

@Configuration
public class ACorsConfig {
    @Value("${cors.allowed-methods:}")
    private List<String> allowedMethods;

    @Value("${cors.allowed-origin-patterns:}")
    private List<String> allowedOriginPatterns;

    @Value("${cors.allowed-headers:}")
    private List<String> allowedHeaders;

    public CorsConfiguration applyCorsConfiguration(HttpSecurity http) throws Exception {
        var havingCors = false;
        var cors = new CorsConfiguration();

        if(!allowedMethods.isEmpty()) {
            cors.setAllowedMethods(allowedMethods);
            havingCors = true;
        }

        if(!allowedHeaders.isEmpty()) {
            cors.setAllowedHeaders(allowedHeaders);
            havingCors = true;
        }

        if (!allowedOriginPatterns.isEmpty()) {
            allowedOriginPatterns.stream().forEach(cors::addAllowedOriginPattern);
            havingCors = true;
        }

        if (havingCors && Objects.nonNull(http)) {
            http.cors().configurationSource(request -> cors);
        }
        return cors;
    }

}
