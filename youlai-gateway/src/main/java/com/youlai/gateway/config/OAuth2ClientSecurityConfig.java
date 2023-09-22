package com.youlai.gateway.config;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.List;


/**
 * Security 安全配置
 *
 * @author haoxr
 * @date 2022/8/28
 */
@ConfigurationProperties(prefix = "security")
@EnableWebFluxSecurity
@Slf4j
public class OAuth2ClientSecurityConfig {

    @Setter
    private List<String> ignoreUrls;


    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        if (ignoreUrls == null) {
            log.error("failed to read ignoreUrls configuration,please check your nacos connection or configuration!");
        }

        http
                // 请求鉴权配置
                .authorizeExchange(authorizeExchangeSpec ->
                        authorizeExchangeSpec
                                .pathMatchers("/**").permitAll()
                                .anyExchange().authenticated()
                ).oauth2Login(s->s.)
                // 禁用csrf token安全校验
                .csrf(csrf->csrf.disable()) ;
        return http.build();
    }


}