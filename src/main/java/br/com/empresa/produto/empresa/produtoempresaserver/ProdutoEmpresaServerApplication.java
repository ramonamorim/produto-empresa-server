package br.com.empresa.produto.empresa.produtoempresaserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.data.mongodb.repository.config.EnableReactiveMongoRepositories;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;

@SpringBootApplication
@EnableWebFluxSecurity
@EnableEurekaClient
@EnableReactiveMongoRepositories
public class ProdutoEmpresaServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProdutoEmpresaServerApplication.class, args);
	}
}
