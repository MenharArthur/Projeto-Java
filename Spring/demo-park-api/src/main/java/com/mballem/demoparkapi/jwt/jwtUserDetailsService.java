package com.mballem.demoparkapi.jwt;

import com.mballem.demoparkapi.entity.Usuario;
import com.mballem.demoparkapi.service.UsuarioService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
//A classe implementada serve para localizar o usuário no banco de dados.
public class jwtUserDetailsService implements UserDetailsService {

    private final UsuarioService usuarioService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario usuario = usuarioService.buscarPorUsername(username);
        return new jwtUserDetails(usuario);
    }

    public jwtToken getTokenAuthenticated(String username){
        Usuario.Role role = usuarioService.buscarRolePorUsername(username);
        return jwtUtils.createToken(username, role.name().substring("ROLE_".length()));
    }
}
