package dev.bermeb.authora;

import dev.bermeb.authora.config.AuthoraProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AuthoraProperties.class)
public class AuthoraApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthoraApplication.class, args);
    }

}
