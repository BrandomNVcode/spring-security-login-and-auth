package com.bolsadeideas.springboot.app.auth.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

//import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.bolsadeideas.springboot.app.auth.service.JWTService;
import com.bolsadeideas.springboot.app.auth.service.JWTServiceImpl;
import com.bolsadeideas.springboot.app.models.entity.Usuario;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

//import io.jsonwebtoken.security.Keys;


public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	//public static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);


	private AuthenticationManager authenticationManager;
	private JWTService jwtService;
	
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
		this.authenticationManager = authenticationManager;
		this.jwtService = jwtService;
		setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
	}



	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		String username = obtainUsername(request); // o request.getParameter("username")
		String password = obtainPassword(request);
		
		if(username != null && password != null) { // para form-data
			logger.info("Username desde request parameter (form-data): " + username);
			logger.info("Password desde request parameter (form-data): " + password);
		} else {
			// cuando se pasa como json
			
			Usuario user = null;
			try {
				user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);
				username = user.getUsername();
				password = user.getPassword();
				
				logger.info("Username desde request parameter (getInputStream): " + username);
				logger.info("Password desde request parameter (getInputStream): " + password);
				
			} catch (JsonParseException e) {
				e.printStackTrace();
			} catch (JsonMappingException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			
		}

		username = username.trim();
		
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
		
		
		return authenticationManager.authenticate(authToken);
	}



	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		String token = jwtService.create(authResult);
		
		// agregamos el token al header (una forma de pasar el token)
		response.addHeader(JWTServiceImpl.HEADER_STRING, JWTServiceImpl.TOKEN_PREFIX + token);
		
		Map<String, Object> body = new HashMap<>();
		body.put("token", token);
		body.put("user", ((User) authResult.getPrincipal()));
		body.put("mensaje", "Hola, " + authResult.getName() + ", inició sesión correctamente");
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(200);
		response.setContentType("application/json");
		
	}


	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		
		Map<String, Object> body = new HashMap<>();
		body.put("mensaje", "Error de acceso. Credenciales incorrectas!!");
		body.put("error", failed.getMessage());
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(200);
		response.setContentType("application/json");
	}
	
	
	
	
}
