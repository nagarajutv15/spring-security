package com.example.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

//	@Bean
//	public KafkaAdmin.NewTopics topics456() {
//		return new KafkaAdmin.NewTopics(
//				TopicBuilder.name("email-verification")
//						.build());
//	}

}
