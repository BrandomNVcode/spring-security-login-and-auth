package com.bolsadeideas.springboot.app.view.json;

import java.util.Map;

import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

public class ClienteListJsonView extends MappingJackson2JsonView {

	@Override
	protected Object filterModel(Map<String, Object> model) {
		
		model.remove("titulo");
		model.remove("page");
		
		return super.filterModel(model);
	}

	
}
