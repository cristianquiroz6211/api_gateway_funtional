package com.example.apigateway.config;

import com.example.apigateway.core.helpers.ObjectHelper;
import com.example.apigateway.core.interfaces.AuthenticationConverter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class CustomJwtAuthenticationConverter implements AuthenticationConverter {

    @Override
    @SuppressWarnings("unchecked")
    public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        return Mono.just(new JwtAuthenticationToken(jwt, authorities));
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        List<String> permissions = new ArrayList<>();

        if (!ObjectHelper.isNull(jwt.getClaim("permissions"))) {
            permissions.addAll(jwt.getClaimAsStringList("permissions"));
        }

        if (!ObjectHelper.isNull(jwt.getClaim("scope"))) {
            permissions.addAll(jwt.getClaimAsStringList("scope"));
        }

        if (!ObjectHelper.isNull(jwt.getClaim("realm_access"))) {
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess.containsKey("roles")) {
                List<String> roles = (List<String>) realmAccess.get("roles");
                permissions.addAll(roles.stream()
                        .map(role -> "ROLE_" + role.toUpperCase())
                        .toList());
            }
        }

        return permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
