package br.com.empresa.produto.empresa.produtoempresaserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;

@Configuration
@EnableReactiveMethodSecurity
@EnableResourceServer
public class SecurityConfiguration extends ResourceServerConfigurerAdapter {

	// private ServerAuthenticationEntryPoint entryPoint = new
	// JwtAuthenticationEntryPoint();

	// private final CustomReactiveUserDetailsService userDetailsService;
	// private final CustomAuthenticationConverter customAuthenticationConverter;

	// public SecurityConfiguration(CustomReactiveUserDetailsService
	// userDetailsService,
	// CustomAuthenticationConverter customAuthenticationConverter) {
	// Assert.notNull(userDetailsService, "userDetailsService cannot be null");
	// Assert.notNull(customAuthenticationConverter, "customAuthenticationConverter
	// cannot be null");
	// this.userDetailsService = userDetailsService;
	// this.customAuthenticationConverter = customAuthenticationConverter;
	// }
	private final static String resourceId = "resources";

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) {
		resources.resourceId(resourceId);
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		// http.requestMatcher(new
		http.requestMatcher(new RequestHeaderRequestMatcher("Authorization")).authorizeRequests().antMatchers("/**")
				.authenticated();

		// http.requestMatchers().antMatchers("/**/").and().authorizeRequests().anyRequest().authenticated();
	}

	@Bean
	SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) throws Exception {

		http.httpBasic().disable();
		http.formLogin().disable();
		http.csrf().disable();
		http.logout().disable();

		// http.authenticationManager(authenticationManager());
		// Add custom security.

		// Disable authentication for `/resources/**` routes.
		http.authorizeExchange().pathMatchers("/resources/**").permitAll();
		http.authorizeExchange().pathMatchers("/webjars/**").permitAll();

		// Disable authentication for `/test/**` routes.
		http.authorizeExchange().pathMatchers("/test/**").permitAll();

		// Disable authentication for `/auth/**` routes.
		http.authorizeExchange().pathMatchers("/auth/**").permitAll();

		// http.securityContextRepository(securityContextRepository());

		http.authorizeExchange().anyExchange().authenticated();
		// .and().httpBasic().disable();
		// http.addFilterAt(apiAuthenticationWebFilter(),
		// SecurityWebFiltersOrder.AUTHENTICATION);
		// http.addFilterAt(apiAuthenticationWebFilter(),
		// SecurityWebFiltersOrder.AUTHENTICATION);
		// .httpBasic().disable().csrf().disable();

		return http.build();
	}

	// @Bean
	// public ServerAuthenticationEntryPoint securityContextRepository() {
	// return entryPoint;
	// // }
	// private AuthenticationWebFilter apiAuthenticationWebFilter() {
	// try {
	// AuthenticationWebFilter apiAuthenticationWebFilter = new
	// AuthenticationWebFilter(authenticationManager());
	// apiAuthenticationWebFilter
	// .setAuthenticationFailureHandler(new
	// ServerAuthenticationEntryPointFailureHandler(this.entryPoint));
	// apiAuthenticationWebFilter.setAuthenticationConverter(this.customAuthenticationConverter);
	// apiAuthenticationWebFilter
	// .setRequiresAuthenticationMatcher(new
	// PathPatternParserServerWebExchangeMatcher("/api/**"));
	//
	// // Setting the Context Repo helped, not sure if I need this
	// apiAuthenticationWebFilter.setSecurityContextRepository(securityContextRepository());
	//
	// return apiAuthenticationWebFilter;
	// } catch (Exception e) {
	// throw new BeanInitializationException(
	// "Could not initialize AuthenticationWebFilter apiAuthenticationWebFilter.",
	// e);
	// }
	// }

}