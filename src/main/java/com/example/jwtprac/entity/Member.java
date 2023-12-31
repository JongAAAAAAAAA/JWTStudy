package com.example.jwtprac.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Set;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Member {
    @Id
    @Column(name = "member_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String password;

    private String nickname;

    // 회원의 가입 승인 여부를 판단하는 필드
    private boolean activated;

    // @ManyToMany 와 @JoinTable 은 member 객체와 권한객체의 다대다 관계를
    // 일대다, 다대일 관계의 조인 테이블로 정했다는 뜻 -> 다대다 해소
    @ManyToMany
    @JoinTable(
            name = "member_authority", //테이블 이름
            joinColumns = @JoinColumn(name = "member_id", referencedColumnName = "member_id"), // 현재 엔티티를 참조하는 외래 키
            inverseJoinColumns = @JoinColumn(name = "authority_name", referencedColumnName = "authority_name") // 반대방향 엔티티를 참조하는 외래 키
    )
    private Set<Authority> authorities;
}
