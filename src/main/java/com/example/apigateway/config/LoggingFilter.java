package com.example.apigateway.config;

import com.example.apigateway.core.helpers.ObjectHelper;
import com.example.apigateway.core.interfaces.RequestLoggingFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import org.springframework.security.core.context.SecurityContext;

@Component
public class LoggingFilter implements RequestLoggingFilter {

    private static final Logger logger = LoggerFactory.getLogger(LoggingFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .switchIfEmpty(Mono.empty())
                .flatMap(authentication -> {
                    if (!ObjectHelper.isNull(authentication) && authentication instanceof JwtAuthenticationToken) {
                        logger.info("Request is valid: {}", exchange.getRequest().getURI());
                    } else {
                        logger.warn("Request is invalid: {}", exchange.getRequest().getURI());
                    }
                    return chain.filter(exchange);
                });

    }
}
