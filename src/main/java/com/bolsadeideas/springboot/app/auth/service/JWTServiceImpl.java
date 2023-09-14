package com.bolsadeideas.springboot.app.auth.service;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;

import com.bolsadeideas.springboot.app.auth.SimpleGrantedAuthoritiesMixin;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JWTServiceImpl implements JWTService {
	
	public static final String SECRET = Base64Utils.encodeToString("MI CLAVE SECRETA 123".getBytes());
	public static final Long EXPIRATION_TIME = 3600000L*24;  // 3600000 = 1 hora
	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String HEADER_STRING = "Authorization";

	@Override
	public String create(Authentication auth) throws IOException {
		
		String username = auth.getName();
		
		// Generamos el claim para pasar los roles
		Collection<? extends GrantedAuthority> roles = auth.getAuthorities();
		
		Claims claims = Jwts.claims();
		claims.put("roles", new ObjectMapper().writeValueAsString(roles));
		
		// Generamos el token
		String token = Jwts.builder()
				.setClaims(claims)
				.setSubject(username)
				.signWith(SignatureAlgorithm.HS512, SECRET.getBytes())
				.setIssuedAt(new  Date()) // fecha de creacion
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
				.compact();
		
		return token;
	}

	@Override
	public boolean validate(String token) {
		try {
			getClaims(token);
			return true;
		} catch (JwtException | IllegalArgumentException e) {
			return false;
		}
	}

	@Override
	public Claims getClaims(String token) {
		Claims claims = Jwts.parser()
				.setSigningKey(SECRET.getBytes())
				.parseClaimsJws(resolve(token))
				.getBody();
		
		return claims;
	}

	@Override
	public String getUsername(String token) {
		return getClaims(token).getSubject();
	}

	@Override
	public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException {
		Object roles = getClaims(token).get("roles"); // cuando creamos el token y guardamos los roles: claims.put("roles", new ObjectMapper().writeValueAsString(roles));
		Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
				.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthoritiesMixin.class)
				.readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
		return authorities;
	}

	@Override
	public String resolve(String token) {
		if(token != null && token.startsWith(TOKEN_PREFIX)) {			
			return token.replace(TOKEN_PREFIX, "");
		}
		return null;
	}

}
