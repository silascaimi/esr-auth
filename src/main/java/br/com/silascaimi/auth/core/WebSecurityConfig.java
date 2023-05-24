package br.com.silascaimi.auth.core;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	// Configurando autenticação de usuários em memória com uso da função para encriptar com BCrypt
	// removido após implementação para busca de usuários no banco de dados
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.inMemoryAuthentication()
//			.withUser("silas")
//				.password(passwordEncoder().encode("123"))
//				.roles("ADMIN")
//			.and()
//				.withUser("joao")
//				.password(passwordEncoder().encode("123"))
//				.roles("ADMIN");
//	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//http.csrf().disable();  //Desativado CSRF
		
		// Configuração necessária para uso do fluxo authorization code
		http
			.authorizeRequests()
				.anyRequest().authenticated()
	         .and()
	         	.formLogin().permitAll();
		
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	// registra um bean do authentication manager usado no autenticationServer para uso do password flow
	@Bean
	@Override
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}
	
	// Cria o bean de user details service para usar refresh token
	// removido após implementação para busca de usuários no banco de dados
//	@Bean
//	@Override
//	protected UserDetailsService userDetailsService() {
//		return super.userDetailsService();
//	}
}