package br.com.silascaimi.auth.core;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@SuppressWarnings("deprecation")
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter{

	@Autowired
	private PasswordEncoder passwordEncode;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties;
	
//	@Autowired
//	private RedisConnectionFactory redisConnectionFactory;
	
	// Configurando os clientes que podem acessar o authorization em memória
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory()
				.withClient("esr-web")
				.secret(passwordEncode.encode("web123"))
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("write", "read")
				.accessTokenValiditySeconds(60 * 60 * 6) // 6 horas
				.refreshTokenValiditySeconds(60 * 24 * 60 * 60) // 60 dias
			.and()
				.withClient("faturamento")
				.secret(passwordEncode.encode("faturamento123"))
				.authorizedGrantTypes("client_credentials")
				.scopes("write", "read")
			.and()
				.withClient("foodanalystics")
				.secret(passwordEncode.encode("food123"))
				.authorizedGrantTypes("authorization_code")
				.scopes("write", "read")
				.redirectUris("http://www.foodanalytics.local:8082")
			.and()
				.withClient("webadmin")
				.authorizedGrantTypes("implicit")
				.scopes("write", "read")
				.redirectUris("http://aplicacao-cliente")
			.and()
				.withClient("checktoken")
				.secret(passwordEncode.encode("checktoken"))
				.authorizedGrantTypes("password")
				.scopes("write", "read");
	}
	
	// Configurar o acesso ao endpoint check_token
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		//security.checkTokenAccess("isAuthenticated()");
		security.checkTokenAccess("permitAll()") // permitindo acesso sem autenticação do client
			//.allowFormAuthenticationForClients(); // permitir que o cliente autentique passando as credenciais como parametros
			.tokenKeyAccess("permitAll()");
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		var enhancerChain = new TokenEnhancerChain();
		enhancerChain.setTokenEnhancers(Arrays.asList(new JwtCustomClaimsTokenEnhancer(), jwtAccessTokerConverter()));
		
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService) // especifica o userDetailsService para trabalhar com refreshtoken
			.reuseRefreshTokens(false)
			//.tokenStore(redisTokenStore())
			.accessTokenConverter(jwtAccessTokerConverter())
			.tokenEnhancer(enhancerChain)
			.approvalStore(approvalTokenStore(endpoints.getTokenStore()))
			.tokenGranter(tokenGranter(endpoints));
	}
	
	private ApprovalStore approvalTokenStore(TokenStore tokenStore) {
		var approvalStore = new TokenApprovalStore();
		approvalStore.setTokenStore(tokenStore);
		return approvalStore;
	}
	
	// remove configurações do redis para inclusão de jwt
//	private TokenStore redisTokenStore() {
//		return new RedisTokenStore(redisConnectionFactory);
//	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokerConverter() {
		JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
		//jwtAccessTokenConverter.setSigningKey("a17c5fef0b9d41719d72b1014903f269");
		
		var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
		var keyStorePass = jwtKeyStoreProperties.getPassword();
		var keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();
		
		var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
		var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
		
		jwtAccessTokenConverter.setKeyPair(keyPair);
		
		return jwtAccessTokenConverter;
	}
	
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
}
