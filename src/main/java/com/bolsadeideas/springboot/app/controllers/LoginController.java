package com.bolsadeideas.springboot.app.controllers;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class LoginController {

	
	@GetMapping("/login")
	public String login(
			@RequestParam(value="error", required = false) String error, 
			@RequestParam(value="logout", required = false) String logout, 
			Model model, 
			Principal principal, 
			RedirectAttributes flash) 
	{
		
		// con el principal vemos si el usuario
		// ya ha iniciado sesion
		
		//System.out.print("PRINCIPAL: " + principal);
		
		if(principal != null) {
			flash.addFlashAttribute("info", "Ya ha iniciado sesión anteriormente");
			return "redirect:/";
		}
		
		if(error != null) {
			model.addAttribute("error", "Error en el login. Credenciales incorrectas.");
		}
		
		if(logout != null) {
			model.addAttribute("success", "Se cerro la sesión con exito.");
		}
		
		
		return "/login";
	}
	
	
}
