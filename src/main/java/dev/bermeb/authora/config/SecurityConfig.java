package dev.bermeb.authora.config;

import dev.bermeb.authora.filter.JwtAuthenticationFilter;
import dev.bermeb.authora.filter.RateLimitFilter;
import dev.bermeb.authora.security.CustomOAuth2UserService;
import dev.bermeb.authora.security.OAuth2AuthenticationFailureHandler;
import dev.bermeb.authora.security.OAuth2AuthenticationSuccessHandler;
import dev.bermeb.authora.security.PepperedPasswordEncoder;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import java.util.List;
import java.util.Optional;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final RateLimitFilter rateLimitFilter;
    private final UserDetailsService userDetailsService;
    private final AuthoraProperties properties;
    private final AuthenticationEntryPoint authEntryPoint;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2SuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2FailureHandler;
    private final Optional<ClientRegistrationRepository> clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) {
        http
                // CSRF protection is unnecessary for stateless JWT APIs
                .csrf(AbstractHttpConfigurer::disable)
                // Apply CORS rules to control which browser origins can make cross-origin requests
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // Never create or use an HTTP session, every request is independently authenticated
                .sessionManagement(
                        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // When an unauthenticated request hits a protected endpoint, delegate to our
                // JwtAuthenticationEntryPoint which returns a JSON 401 response
                .exceptionHandling(ex -> ex.authenticationEntryPoint(authEntryPoint))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST,
                                "/api/v1/auth/register",
                                "/api/v1/auth/login",
                                "/api/v1/auth/refresh",
                                "/api/v1/auth/password/forgot",
                                "/api/v1/auth/password/reset",
                                "/api/v1/auth/oauth2/exchange"
                        ).permitAll()

                        .requestMatchers(HttpMethod.GET,
                                "/api/v1/auth/email/verify",
                                "/api/v1/auth/oauth2/**"
                        ).permitAll()

                        .requestMatchers(
                                "/static/**",
                                "/actuator/health"
                        ).permitAll()

                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider());

        if (properties.getFeatures().isOauth2Enabled() && clientRegistrationRepository.isPresent()) {
            http.oauth2Login(oauth2 -> oauth2
                    .userInfoEndpoint(ui -> ui.userService(customOAuth2UserService))
                    .successHandler(oAuth2SuccessHandler)
                    .failureHandler(oAuth2FailureHandler)
            );
        }

        // Insert both filters before Spring's default username/password filter.
        // Order within the "before" position matters:
        //   1. RateLimitFilter runs first (cheapest check; no DB hit needed)
        //   2. JwtAuthenticationFilter runs second (parses JWT and loads user from DB)
        // Filter order: RateLimitFilter -> JwtAuthenticationFilter -> UsernamePasswordAuthenticationFilter
        // Using addFilterAfter to anchor jwtAuthenticationFilter relative to rateLimitFilter explicitly,
        // rather than both using the same UsernamePasswordAuthenticationFilter anchor (undefined order).
        http
                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(jwtAuthenticationFilter, RateLimitFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // bCrypt Strength 12 is around 300ms
        return new PepperedPasswordEncoder(12, properties.getPasswordPolicy().getPepper());
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) {
        return config.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(properties.getCors().getAllowedOrigins());
        config.setAllowedMethods(properties.getCors().getAllowedMethods());
        // Allow all request headers
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(properties.getCors().isAllowedCredentials());
        // Cache the preflight OPTIONS response for this many seconds (reduces round-trips)
        config.setMaxAge(properties.getCors().getMaxAge());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Apply the same CORS configuration to every URL pattern
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}