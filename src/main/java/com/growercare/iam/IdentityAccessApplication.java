package com.growercare.iam;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.growercare")
public class IdentityAccessApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdentityAccessApplication.class, args);
    }
}
