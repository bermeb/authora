package dev.bermeb.authora;

import dev.bermeb.authora.config.AuthoraProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableAsync
@EnableScheduling
@EnableConfigurationProperties(AuthoraProperties.class)
public class AuthoraApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthoraApplication.class, args);
    }

}
