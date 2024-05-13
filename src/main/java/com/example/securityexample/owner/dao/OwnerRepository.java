package com.example.securityexample.owner.dao;

import com.example.securityexample.owner.domain.Owner;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OwnerRepository extends JpaRepository<Owner, Long> {
    Optional<Owner> findByEmail(String username);
}
