package com.yugi.cauth.config;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

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

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

//設定クラスの宣言 クラス内のメソッドはspringコンテナの管理配下におかれアプリケーション内でのBeanの生成と管理を行う
@Configuration
//Spring Securityの設定を使うことを宣言
@EnableWebSecurity
public class SecurityConfig {


    @Bean //Springコンテナによってインスタンス化、構成、管理されるオブジェクトである宣言
    @Order(1) //Springコンテナ内でのBeanの読み込み順序を指定
    //OAuth 2.0認証サーバーのセキュリティ設定を行うクラス
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        // OAuth 2.0認証サーバーのデフォルトセキュリティ設定を適用
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        // OpenID Connect 1.0のサポートを有効化する。
        // IDトークンの発行やユーザー情報の取得など、OpenID Connectの機能が利用可能
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        // 認証エンドポイントに未認証でアクセスした場合の例外処理を定義する
        // 未認証のユーザーをログインページ（"/login"）にリダイレクトする
        http.exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // リソースサーバーにおけるjwtの認証を行う
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));
        // HttpSecurity オブジェクトの構築を完了し、構成された SecurityFilterChain オブジェクトを生成して返す
        return http.build();
    }

    @Bean
    @Order(2)
    //WEBアプリケーション全般のセキュリティ設定を行うクラス
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        // すべてのHTTPリクエストに対して認証を必要とすることを指定
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                // 認証サーバーフィルターチェーンからログインページへのリダイレクトを処理する
                .formLogin(Customizer.withDefaults());
        // HttpSecurity オブジェクトの構築を完了し、構成された SecurityFilterChain オブジェクトを生成して返す
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        // ユーザーの認証情報を設定するためのビルダー
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        // メモリ上にユーザー情報を保持する
        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    // OAuth 2.0/OpenID Connectクライアント設定をし、それをアプリケーションメモリに保存する
    public RegisteredClientRepository registeredClientRepository() {
        // 新しいクライアントインスタンスを作成し、一意のIDを割り当てる
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                // クライアントのIDを設定。OAuth2.0プロセスでクライアントを識別するため
                .clientId("oidc-client")
                //　クライアントのパスワードを設定（noopはパスワードエンコードを使用しないことを意味する）
                .clientSecret("{noop}secret")
                //　HTTP Basic認証を用いてクライアントIDとクライアントシークレットを認証サーバーに送信
                // HTTP Basic認証: クライアントIDとクライアントシークレットがコロン（:）で連結され、
                // Base64エンコードされた後、HTTPリクエストのAuthorizationヘッダにBasicスキーマと共に追加される
                // クライアント認証のプロセス
                // リクエストの準備: クライアントは、クライアントIDとクライアントシークレットをコロンで連結し、Base64でエンコードする（例: client_id:client_secret -> Base64エンコード）。
                // 認証ヘッダの追加: エンコードされた文字列は、HTTPリクエストのAuthorizationヘッダにBasic [エンコードされた文字列]の形式で追加される。
                // 認証サーバーはこのヘッダを受け取り、Base64デコードを行ってクライアントIDとシークレットを取り出し、保存されている情報と照合してクライアントを認証する
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // クライアントがアクセストークンを取得するための方法を定めている
                // ユーザーのブラウザを通じて認証と認可を行う
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // 有効期限が切れたアクセストークンを新しいトークンと交換するために使用される
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // ログインして認証を完了した後に、ユーザーがリダイレクトされる場所を指定
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
                // ログアウトした後にリダイレクトされるURIを指定するための設定
                .postLogoutRedirectUri("http://127.0.0.1:8080/")
                // アプリケーションがユーザーのアカウントにアクセスして行うことができる操作の範囲を指定する
                // 基本的なプロファイル情報（ID,ユーザー名）へのアクセスを要求する
                .scope(OidcScopes.OPENID)
                // 詳細なプロファイル情報（名前、社員）へのアクセスを要求する
                //　Emailを指定するとユーザーのメールアドレスへのアクセスを要求する
                .scope(OidcScopes.PROFILE)
                // 明示的な同意を求める画面を表示する設定
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(oidcClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
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
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

}