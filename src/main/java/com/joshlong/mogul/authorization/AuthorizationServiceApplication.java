package com.joshlong.mogul.authorization;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.net.URI;
import java.util.Set;

/**
 * Provides the centralized OAuth authorization service for all my infrastructure going
 * forward.
 *
 * @author Josh Long
 */
// @EnableConfigurationProperties(AuthorizationApiProperties.class)
@SpringBootApplication
@ImportRuntimeHints(AuthorizationServiceApplication.Hints.class)
public class AuthorizationServiceApplication {

	static class Hints implements RuntimeHintsRegistrar {

		@Override
		public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
			Set.of("data", "schema").forEach(folder -> hints.resources().registerPattern("sql/" + folder + "/*sql"));
		}

	}

	private final static Logger log = LoggerFactory.getLogger(AuthorizationServiceApplication.class);

	public static void main(String[] args) {
		System.getenv().forEach((k, v) -> System.out.println(k + "=" + v));
		SpringApplication.run(AuthorizationServiceApplication.class, args);
	}

	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)//
			.oidc(Customizer.withDefaults());
		http.exceptionHandling((exceptions) -> //
		exceptions.defaultAuthenticationEntryPointFor(//
				new LoginUrlAuthenticationEntryPoint("/login"), //
				new MediaTypeRequestMatcher(MediaType.TEXT_HTML))//
		)//
			.oauth2ResourceServer((rs) -> rs.jwt(Customizer.withDefaults()));
		return http.build();
	}

	@Bean
	@Order(2)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		return http.authorizeHttpRequests((authorize) -> authorize //
			.requestMatchers(EndpointRequest.toAnyEndpoint())
			.permitAll()//
			.anyRequest()
			.authenticated()//
		)//
			.formLogin(Customizer.withDefaults()) //
			.requiresChannel(c -> c.anyRequest().requiresSecure())
			.build();
	}

	@Bean
	InMemoryUserDetailsManager users(PasswordEncoder passwordEncoder,
			@Value("${AUTHORIZATION_SERVICE_USERS_JLONG_USERNAME:jlong}") String username,
			@Value("${AUTHORIZATION_SERVICE_USERS_JLONG_PASSWORD:pw}") String password) {
		// todo
		log.debug("got the following users: " + username + ":" + password);
		var user = User.withUsername(username)//
			.password(passwordEncoder.encode(password))//
			.roles("user", "admin")//
			.build();
		return new InMemoryUserDetailsManager(user);
	}

	@Bean
	RegisteredClientRepository registeredClients(PasswordEncoder passwordEncoder,
			@Value("${AUTHORIZATION_SERVICE_CLIENTS_MOGUL_CLIENT_ID:mogul}") String clientId,
			@Value("${AUTHORIZATION_SERVICE_CLIENTS_MOGUL_CLIENT_SECRET:mogul}") String clientSecret,
			@Value("${MOGUL_GATEWAY_HOST:http://127.0.0.1:1010}/login/oauth2/code/spring") URI redirectUri) {
		// todo remove this
		log.info("DEBUG: " + clientId + ":" + clientSecret + ":" + redirectUri);
		var rc = RegisteredClient.withId(clientId)
			.clientId(clientId)
			.authorizationGrantTypes(c -> c
				.addAll(Set.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN)))
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.clientSecret(passwordEncoder.encode(clientSecret))
			.redirectUri(redirectUri.toString())
			.scopes(c -> c.addAll(Set.of("user.read", "user.write", "openid")))
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
			.build();
		return new InMemoryRegisteredClientRepository(rc);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

}
