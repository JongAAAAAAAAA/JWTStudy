package com.example.jwtprac.dao;

import com.example.jwtprac.entity.Member;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    // 쿼리가 수행될 때, Lazy가 아닌 Eager조회로 authorities 정보를 같이 가져온다.
    @EntityGraph(attributePaths = "authorities")
    // username을 기준으로 Member 정보 가져올 때, 권한 정보도 같이 가져온다.
    Optional<Member> findOneWithAuthoritiesByUsername(String username);

}
