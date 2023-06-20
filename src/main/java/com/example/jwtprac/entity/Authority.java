package com.example.jwtprac.entity;

import lombok.Getter;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
@Getter
public class Authority {
    @Id
    @Column(name = "authority_name")
    private String authorityName;
}
