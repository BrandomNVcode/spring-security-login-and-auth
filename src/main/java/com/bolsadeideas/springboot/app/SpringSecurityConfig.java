package com.bolsadeideas.springboot.app;

//import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;

import com.bolsadeideas.springboot.app.auth.filter.JWTAuthenticationFilter;
import com.bolsadeideas.springboot.app.auth.filter.JWTAuthorizationFilter;
import com.bolsadeideas.springboot.app.auth.service.JWTService;
//import com.bolsadeideas.springboot.app.auth.handler.LoginSuccessHandler;
import com.bolsadeideas.springboot.app.models.service.JpaUserDetailsService;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private JpaUserDetailsService userDetailsService;
	
    //@Autowired
    //private LoginSuccessHandler successHandler;
    
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    
    @Autowired
    private JWTService jwtService;
    
    //@Autowired
    //private DataSource dataSource; // conexion a la base de datos
    
    
	@Autowired
	public void configurerGlobal(AuthenticationManagerBuilder builder) throws Exception {
		
		// CON JDBC
		/*builder.jdbcAuthentication()
			.dataSource(dataSource)
			.passwordEncoder(passwordEncoder)
			.usersByUsernameQuery("select username, password, enabled from users where username=?")
			.authoritiesByUsernameQuery("select u.username, a.authority from authorities as a inner join users as u on (a.user_id=u.id) where u.username=?");*/
		
		
		// CON JPA
		builder.userDetailsService(userDetailsService)
			.passwordEncoder(passwordEncoder);
		
		
		/*PasswordEncoder encoder = this.passwordEncoder;
		UserBuilder users = User.builder().passwordEncoder(password -> encoder.encode(password));
		
		builder.inMemoryAuthentication()
			.withUser(users.username("admin").password("123456").roles("ADMIN", "USER"))
			.withUser(users.username("andres").password("123456").roles("USER"));*/
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.antMatchers("/", "/css/**", "/js/**", "/images/**", "/listar**").permitAll()
			.anyRequest().authenticated()
			.and()
			.addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtService))
			.addFilter(new JWTAuthorizationFilter(authenticationManager(), jwtService))
			.csrf().disable() // para usar el jwt, y no usar el jwt q nos brinda spring
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}
	
}
