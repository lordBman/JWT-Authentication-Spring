package com.bsoft.jwtauthentication;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.json.JsonTest;
import org.springframework.boot.test.json.JacksonTester;

import com.bsoft.jwtauthentication.controllers.AuthController.JwtResponse;
import com.bsoft.jwtauthentication.controllers.AuthController.LoginRequest;
import com.bsoft.jwtauthentication.controllers.AuthController.MessageResponse;
import com.bsoft.jwtauthentication.controllers.AuthController.SignupRequest;
import com.bsoft.jwtauthentication.controllers.AuthController.TokenRefreshRequest;
import com.bsoft.jwtauthentication.controllers.AuthController.TokenRefreshResponse;

import io.jsonwebtoken.io.IOException;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.*;

@JsonTest
public class PayloadJsonTest {
    @Autowired
    private JacksonTester<SignupRequest> signupJson;

    @Autowired
    private JacksonTester<LoginRequest> loginJson;

    @Autowired
    private JacksonTester<JwtResponse> jwtResponseJson;

    @Autowired
    private JacksonTester<MessageResponse> messageResponseJson;

    @Autowired
    private JacksonTester<TokenRefreshRequest> tokenRefreshRequestJson;

    @Autowired
    private JacksonTester<TokenRefreshResponse> tokenRefreshResponseJson;

    @Test
    void signupRequestSerializationTest() throws IOException, java.io.IOException {
        Set<String> roles = new HashSet<String>();
        roles.add("admin");

        SignupRequest request = new SignupRequest("okelekelenobel@gmail.com",  "Nobel Okelekele", "rustup", roles );
        assertThat(signupJson.write(request)).isStrictlyEqualToJson("signup-request.json");

        assertThat(signupJson.write(request)).hasJsonPathStringValue("@.name");
        assertThat(signupJson.write(request)).extractingJsonPathStringValue("@.name").isEqualTo("Nobel Okelekele");

        assertThat(signupJson.write(request)).hasJsonPathStringValue("@.email");
        assertThat(signupJson.write(request)).extractingJsonPathStringValue("@.email").isEqualTo("okelekelenobel@gmail.com");

        assertThat(signupJson.write(request)).hasJsonPathStringValue("@.password");
        assertThat(signupJson.write(request)).extractingJsonPathStringValue("@.password").isEqualTo("rustup");

        assertThat(signupJson.write(request)).hasJsonPathArrayValue("@.roles");
        assertThat(signupJson.write(request)).extractingJsonPathArrayValue("@.roles").containsExactlyInAnyOrder("admin");
    }

    @Test
    void signupRequestDeserializationTest() throws java.io.IOException {
        String expected = """
            {
                "name": "Blessing Okelekele",
                "email": "blessingokelekele@gmail.com", 
                "password": "myblessing",
                "roles": ["user", "admin"]
            } 
        """;

        HashSet<String> roles = new HashSet<>();
        roles.add("user");
        roles.add("admin");   

        assertThat(signupJson.parse(expected)).isEqualTo(new SignupRequest("blessingokelekele@gmail.com", "Blessing Okelekele", "myblessing", roles));
        assertThat(signupJson.parseObject(expected).name()).isEqualTo("Blessing Okelekele");
        assertThat(signupJson.parseObject(expected).email()).isEqualTo("blessingokelekele@gmail.com");
        assertThat(signupJson.parseObject(expected).roles()).containsExactlyInAnyOrder("user", "admin");
        assertThat(signupJson.parseObject(expected).password()).isEqualTo("myblessing");
    }

    @Test
    void loginRequestSerializationTest() throws IOException, java.io.IOException {

        LoginRequest request = new LoginRequest("okelekelenobel@gmail.com", "rustup" );
        assertThat(loginJson.write(request)).isStrictlyEqualToJson("login-request.json");

        assertThat(loginJson.write(request)).hasJsonPathStringValue("@.email");
        assertThat(loginJson.write(request)).extractingJsonPathStringValue("@.email").isEqualTo("okelekelenobel@gmail.com");

        assertThat(loginJson.write(request)).hasJsonPathStringValue("@.password");
        assertThat(loginJson.write(request)).extractingJsonPathStringValue("@.password").isEqualTo("rustup");
    }

    @Test
    void loginRequestDeserializationTest() throws java.io.IOException {
        String expected = """
            {
                "email": "blessingokelekele@gmail.com", 
                "password": "myblessing"
            } 
        """;

        assertThat(loginJson.parse(expected)).isEqualTo(new LoginRequest("blessingokelekele@gmail.com","myblessing"));
        assertThat(signupJson.parseObject(expected).email()).isEqualTo("blessingokelekele@gmail.com");
        assertThat(signupJson.parseObject(expected).password()).isEqualTo("myblessing");
    }

    @Test
    void jwtResponseSerializationTest() throws IOException, java.io.IOException {

        List<String> roles = new ArrayList<>();
        roles.add("user");
        roles.add("admin");

        JwtResponse response = new JwtResponse("jwttoken", "refreshToken", 2l, "Blessing Okelekele", "blessingokelekele@gmail.com", roles);
        assertThat(jwtResponseJson.write(response)).isStrictlyEqualToJson("jwt-response.json");

        assertThat(jwtResponseJson.write(response)).hasJsonPathStringValue("@.jwt");
        assertThat(jwtResponseJson.write(response)).extractingJsonPathStringValue("@.jwt").isEqualTo("jwttoken");

        assertThat(jwtResponseJson.write(response)).hasJsonPathStringValue("@.refreshToken");
        assertThat(jwtResponseJson.write(response)).extractingJsonPathStringValue("@.refreshToken").isEqualTo("refreshToken");

        assertThat(jwtResponseJson.write(response)).hasJsonPathNumberValue("@.id");
        assertThat(jwtResponseJson.write(response)).extractingJsonPathNumberValue("@.id").isEqualTo(2);

        assertThat(jwtResponseJson.write(response)).hasJsonPathStringValue("@.name");
        assertThat(jwtResponseJson.write(response)).extractingJsonPathStringValue("@.name").isEqualTo("Blessing Okelekele");

        assertThat(jwtResponseJson.write(response)).hasJsonPathStringValue("@.email");
        assertThat(jwtResponseJson.write(response)).extractingJsonPathStringValue("@.email").isEqualTo("blessingokelekele@gmail.com");

        assertThat(jwtResponseJson.write(response)).hasJsonPathArrayValue("@.roles");
        assertThat(jwtResponseJson.write(response)).extractingJsonPathArrayValue("@.roles").containsExactlyInAnyOrder("user", "admin");
    }

    @Test
    void jwtResponseDeserializationTest() throws java.io.IOException {
        String expected = """
            {
                "jwt": "jwttoken",
                "refreshToken": "refreshToken",
                "id": 2,
                "name": "Blessing Okelekele",
                "email": "blessingokelekele@gmail.com",
                "roles": ["user", "admin"]
            } 
        """;

        List<String> roles = new ArrayList<>();
        roles.add("user");
        roles.add("admin");

        assertThat(jwtResponseJson.parse(expected)).isEqualTo(new JwtResponse("jwttoken", "refreshToken", 2l, "Blessing Okelekele", "blessingokelekele@gmail.com", roles));
        assertThat(jwtResponseJson.parseObject(expected).jwt()).isEqualTo("jwttoken");
        assertThat(jwtResponseJson.parseObject(expected).refreshToken()).isEqualTo("refreshToken");
        assertThat(jwtResponseJson.parseObject(expected).id()).isEqualTo(2);
        assertThat(jwtResponseJson.parseObject(expected).name()).isEqualTo("Blessing Okelekele");
        assertThat(jwtResponseJson.parseObject(expected).email()).isEqualTo("blessingokelekele@gmail.com");
        assertThat(jwtResponseJson.parseObject(expected).roles()).containsExactlyInAnyOrder("user", "admin");
    }
}
