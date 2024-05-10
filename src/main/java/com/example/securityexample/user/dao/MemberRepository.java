package com.example.securityexample.user.dao;

import com.example.securityexample.user.domain.Member;
import com.example.securityexample.user.domain.MemberUserDetails;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByEmail(String username);
}
