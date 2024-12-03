package com.mballem.demoparkapi;

import com.mballem.demoparkapi.jwt.jwtToken;
import com.mballem.demoparkapi.web.dto.UsuarioLoginDto;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.function.Consumer;

public class jwtAuthentication {

    public static Consumer<HttpHeaders> getHeadersAuthorization(WebTestClient client, String username, String password){
        String token = client
                .post()
                .uri("/api/v1/auth")
                .bodyValue(new UsuarioLoginDto(username, password))
                .exchange()
                .expectStatus().isOk()
                .expectBody(jwtToken.class)
                .returnResult().getResponseBody().getToken();
        return headers -> headers.add(HttpHeaders.AUTHORIZATION,"Bearer"+token);
    }

}
