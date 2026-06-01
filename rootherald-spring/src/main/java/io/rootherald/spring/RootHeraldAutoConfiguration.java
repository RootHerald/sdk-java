package io.rootherald.spring;

import io.rootherald.AttestationTokenVerifier;
import io.rootherald.JwksFetcher;
import io.rootherald.TokenVerifier;
import io.rootherald.client.RootHeraldClient;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.HandlerMapping;

import java.net.URI;
import java.util.List;

/**
 * Spring Boot auto-configuration for RootHerald. Activates when
 * {@code rootherald.issuer} is set in configuration.
 */
@Configuration
@EnableConfigurationProperties(RootHeraldProperties.class)
@ConditionalOnProperty(prefix = "rootherald", name = "issuer")
@ConditionalOnClass(name = "jakarta.servlet.Filter")
public class RootHeraldAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwksFetcher rootheraldJwksFetcher(RootHeraldProperties props) {
        String uri = props.getJwksUri();
        if (uri == null || uri.isBlank()) {
            String base = props.getBaseUri();
            if (base == null || base.isBlank()) {
                throw new IllegalStateException("rootherald.jwks-uri or rootherald.base-uri must be set");
            }
            uri = base.replaceAll("/$", "") + "/.well-known/jwks.json";
        }
        return new JwksFetcher(URI.create(uri));
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenVerifier rootheraldVerifier(RootHeraldProperties props, JwksFetcher jwks) {
        return AttestationTokenVerifier.builder()
                .issuer(props.getIssuer())
                .audience(props.getAudience())
                .jwksFetcher(jwks)
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public RootHeraldClient rootheraldClient(RootHeraldProperties props, TokenVerifier verifier) {
        return RootHeraldClient.builder()
                .baseUri(props.getBaseUri())
                .issuer(props.getIssuer())
                .audience(props.getAudience())
                .apiKey(props.getApiKey())
                .verifier(verifier)
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public RootHeraldGuardFilter rootheraldGuardFilter(
            RootHeraldProperties props,
            TokenVerifier verifier,
            RootHeraldClient client,
            @Autowired(required = false) List<HandlerMapping> handlerMappings) {
        boolean online = "online".equalsIgnoreCase(props.getMode());
        return new RootHeraldGuardFilter(verifier, client, online,
                handlerMappings == null ? List.of() : handlerMappings);
    }
}
