package com.yugi.cauth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));

        return http.cors(Customizer.withDefaults()).build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/private/resource").authenticated()  // "/private/resource"へのリクエストにのみ認証を要求
                        .anyRequest().permitAll()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.cors(Customizer.withDefaults()).build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.addAllowedOrigin("http://localhost:3000");
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        //TODO デバックコメント
        System.out.println("userDetailsService");
        // ユーザーの認証情報を設定するためのビルダー
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("suwa")
                .password("password")
                .roles("ADMIN")
                .build();
        // メモリ上にユーザー情報を保持する
        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient publicClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("public-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:3000/callback")
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build()
                )
                .build();

        return new InMemoryRegisteredClientRepository(publicClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        //TODO デバックコメント
        System.out.println("jwkSource");
        // RSA鍵ペアの生成
        KeyPair keyPair = generateRsaKey();
        // 生成された鍵ペアから公開鍵を取得する
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        // 生成された鍵ペアから秘密鍵を取得する
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        // RSA鍵ビルダーの初期化
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                //ユニークな識別子（KeyID）をRSAKeyに割り当てる
                .keyID(UUID.randomUUID().toString())
                .build();
        //作成したRSAKeyを含む新しいJWKSetを作成する。JWKSetは一つ以上のJWKを含むことができる
        JWKSet jwkSet = new JWKSet(rsaKey);
        //作成したJWKSetをImmutableJWKSetにラップして返却
        return new ImmutableJWKSet<>(jwkSet);
    }

    //RSA暗号化アルゴリズムを用いて、2048ビットの鍵長でKeyPair（公開鍵と秘密鍵のペア）を生成するメソッド
    private static KeyPair generateRsaKey() {
        //TODO デバックコメント
        System.out.println("generateRsaKey");
        KeyPair keyPair;
        try {
            // RSA暗号アルゴリズムを使用する
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            // 鍵ペアジェネレータを2048ビットの鍵長で初期化する
            keyPairGenerator.initialize(2048);
            // RSA鍵ペア（公開鍵と秘密鍵のペア）を生成する
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    //受信したJWTを出コードして信頼できるものであるかを確認する
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        //TODO デバックコメント
        System.out.println("jwkSource");
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    //OAuth 2.0認証サーバーの設定を生成するためのメソッド
    //AuthorizationServerSettingsオブジェクトを生成し、それをアプリケーションの他の部分で再利用可能な形で提供する
    public AuthorizationServerSettings authorizationServerSettings() {
        //TODO デバックコメント
        System.out.println("authorizationServerSettings");
        return AuthorizationServerSettings.builder().build();
    }
}
