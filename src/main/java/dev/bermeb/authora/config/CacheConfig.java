package dev.bermeb.authora.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
public class CacheConfig {

    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager manager = new CaffeineCacheManager();

        manager.registerCustomCache("rateLimitBuckets",
                Caffeine.newBuilder().
                        expireAfterAccess(1, TimeUnit.HOURS)
                        .maximumSize(100_000)
                        .build()
        );

        manager.registerCustomCache("emailVerificationTokens",
                Caffeine.newBuilder().
                        expireAfterWrite(1, TimeUnit.HOURS)
                        .maximumSize(10_000)
                        .build()
        );

        manager.registerCustomCache("oauth2PendingTokens",
                Caffeine.newBuilder()
                        .expireAfterWrite(2, TimeUnit.MINUTES)
                        .maximumSize(1_000)
                        .build()
                );

        return manager;
    }
}