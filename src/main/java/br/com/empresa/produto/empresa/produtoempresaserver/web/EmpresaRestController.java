package br.com.empresa.produto.empresa.produtoempresaserver.web;

import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8_VALUE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Flux;

@RestController
@RequestMapping(path = "/api/empresa", produces = { APPLICATION_JSON_UTF8_VALUE })
public class EmpresaRestController {

	@RequestMapping(method = GET)
	public Flux<String> privateMessageAdmin() {
		return Flux.just("testeROLE DE ADMIN");
		
	}

}
