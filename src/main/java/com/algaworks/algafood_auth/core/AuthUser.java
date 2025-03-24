package com.algaworks.algafood_auth.core;

import com.algaworks.algafood_auth.core.domain.Usuario;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Collections;

@Getter
public class AuthUser extends User {
    private Long userId;
    private String fullname;

    public AuthUser(Usuario usuario, Collection<? extends GrantedAuthority> authorities) {
        super(usuario.getEmail(), usuario.getSenha(), authorities);
        this.fullname = usuario.getNome();
        this.userId = usuario.getId();
    }
}
