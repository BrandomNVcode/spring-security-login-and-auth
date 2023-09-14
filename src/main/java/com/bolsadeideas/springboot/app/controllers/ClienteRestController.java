package com.bolsadeideas.springboot.app.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bolsadeideas.springboot.app.models.entity.Cliente;
import com.bolsadeideas.springboot.app.models.service.IClienteService;

@RestController
@RequestMapping("/api/clientes")
public class ClienteRestController {
	
	@Autowired
	private IClienteService clienteService;

	@GetMapping(value = "/listar")
	@Secured(value = "ROLE_USER")
	public List<Cliente> listar() {
		List<Cliente> clientes = clienteService.findAll();
		return clientes;
	}
	
}
