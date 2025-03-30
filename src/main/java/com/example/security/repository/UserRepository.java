package com.example.security.repository;

import com.example.security.entity.User;
import com.example.security.enums.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String token);

    User findByRole(Role role);

    List<User> findAllByRole(Role role);

}
