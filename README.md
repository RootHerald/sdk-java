# Root Herald — Java SDK

Backend SDK for verifying [Root Herald](https://rootherald.io) device attestation JWTs from Java applications. Plain Java + Spring Boot integration.

## Install

### Maven

```xml
<dependency>
  <groupId>io.rootherald</groupId>
  <artifactId>rootherald-client</artifactId>
  <version>0.1.0</version>
</dependency>
```

### Gradle

```kotlin
implementation("io.rootherald:rootherald-client:0.1.0")
```

Requires Java 17 or later.

## 30-second integration (plain Java)

```java
import io.rootherald.client.RootHeraldClient;
import io.rootherald.client.VerifyResult;

var client = RootHeraldClient.builder()
    .issuer("https://api.rootherald.io")
    .audience("plat_your_client_id")
    .build();

VerifyResult result = client.verify(token);
if (!"pass".equals(result.device().verdict())) {
    response.setStatus(403);
    return;
}
System.out.println("device: " + result.device().deviceId());
```

## Spring Boot integration

```java
@Configuration
@EnableConfigurationProperties(RootHeraldProperties.class)
public class RootHeraldConfig {
    @Bean
    public RootHeraldClient rootHeraldClient(RootHeraldProperties props) {
        return RootHeraldClient.builder()
            .issuer(props.getIssuer())
            .audience(props.getAudience())
            .build();
    }
}
```

```java
@RestController
@RequireRootHerald
public class MeController {
    @GetMapping("/me")
    public Map<String, Object> me(@AttestationVerdict VerifyResult result) {
        return Map.of("deviceId", result.device().deviceId());
    }
}
```

See [`samples/spring-boot-demo`](./samples/spring-boot-demo) for a full working example.

## What you get

- `RootHeraldClient` — JWKS-cached token verifier (Nimbus JOSE-JWT under the hood)
- `@RequireRootHerald` annotation + `@AttestationVerdict` argument resolver for Spring
- Strongly-typed `VerifyResult` + `DeviceVerdict` records
- `WebhookVerifier` for CAEP webhook signature checks (HMAC-SHA256)
- Specific exceptions: `TokenExpiredException`, `WebhookSignatureException`, `RootHeraldException`

## Trust chain

The SDK fetches Root Herald's signing keys from `{issuer}/.well-known/jwks.json` and caches them (default 1 hour, configurable). Verification is local after the initial fetch — no per-request call to Root Herald.

## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
