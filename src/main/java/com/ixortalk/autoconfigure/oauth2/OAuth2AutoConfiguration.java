/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016-present IxorTalk CVBA
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.ixortalk.autoconfigure.oauth2;

import com.ixortalk.autoconfigure.oauth2.auth0.AudienceRequestEntityConverter;
import com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.Auth0ManagementAPI;
import com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.Auth0Roles;
import com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.Auth0Users;
import com.ixortalk.autoconfigure.oauth2.jwt.CustomClaimsProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.Cache;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import javax.inject.Inject;
import java.util.Collection;

import static com.github.benmanes.caffeine.cache.Caffeine.newBuilder;
import static com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.Auth0ManagementAPI.*;
import static java.util.Arrays.stream;
import static java.util.Collections.emptyList;
import static java.util.concurrent.TimeUnit.SECONDS;
import static java.util.stream.Collectors.toSet;
import static org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest.toAnyEndpoint;
import static org.springframework.security.core.authority.AuthorityUtils.createAuthorityList;
import static org.springframework.security.oauth2.client.OAuth2AuthorizeRequest.withClientRegistrationId;
import static org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder.builder;
import static org.springframework.security.oauth2.jwt.JwtDecoders.fromOidcIssuerLocation;
import static org.springframework.security.oauth2.jwt.JwtValidators.createDefaultWithIssuer;

@Configuration
@EnableConfigurationProperties(IxorTalkConfigProperties.class)
public class OAuth2AutoConfiguration {

    @EnableWebSecurity
    public static class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

        @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
        private String issuer;

        @Inject
        private IxorTalkConfigProperties ixorTalkConfigProperties;

        @Inject
        private IxorTalkHttpSecurityConfigurer ixorTalkHttpSecurityConfigurer;

        @Override
        public void configure(HttpSecurity http) throws Exception {
            ixorTalkHttpSecurityConfigurer.configure(http);
            http
                    .csrf().disable()
                    .oauth2ResourceServer()
                    .jwt()
                    .jwtAuthenticationConverter(jwtAuthenticationConverter());
        }

        @Bean
        @ConditionalOnMissingBean(IxorTalkHttpSecurityConfigurer.class)
        public IxorTalkHttpSecurityConfigurer defaultIxorTalkHttpSecurityConfigurer() {
            return http -> http.authorizeRequests().anyRequest().authenticated();
        }

        @Bean
        public JwtAuthenticationConverter jwtAuthenticationConverter() {
            JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
            jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
                if (!jwt.containsClaim(ixorTalkConfigProperties.getSecurity().getJwt().getAuthoritiesClaimName())) {
                    return emptyList();
                }

                Object authorities = jwt.getClaim(ixorTalkConfigProperties.getSecurity().getJwt().getAuthoritiesClaimName());

                if (authorities instanceof Collection) {
                    return ((Collection<String>) authorities).stream().map(SimpleGrantedAuthority::new).collect(toSet());
                } else if (authorities instanceof String) {
                    return stream(((String) authorities).split(" ")).map(SimpleGrantedAuthority::new).collect(toSet());
                }

                return emptyList();
            });
            return jwtAuthenticationConverter;
        }

        @Bean
        @ConditionalOnBean(AudienceValidator.class)
        public JwtDecoder jwtDecoder(AudienceValidator audienceValidator) {
            NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) fromOidcIssuerLocation(issuer);

            OAuth2TokenValidator<Jwt> withIssuer = createDefaultWithIssuer(issuer);
            OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);

            jwtDecoder.setJwtValidator(withAudience);

            return jwtDecoder;
        }

        @Bean
        public GrantedAuthorityDefaults grantedAuthorityDefaults() {
            return new GrantedAuthorityDefaults("");
        }

        @Configuration(proxyBeanMethods = false)
        @ConditionalOnProperty(value = "ixortalk.actuator.security.disabled", havingValue = "true")
        @Order(99)
        public static class ActuatorSecurity extends WebSecurityConfigurerAdapter {

            @Override
            protected void configure(HttpSecurity http) throws Exception {
                http.requestMatcher(toAnyEndpoint())
                        .csrf().disable()
                        .authorizeRequests((requests) -> requests.anyRequest().permitAll());
            }
        }

        @Bean
        @ConditionalOnProperty("ixortalk.security.jwt.custom-claims-namespace")
        public CustomClaimsProvider customClaimsProvider() {
            return new CustomClaimsProvider();
        }
    }

    @Configuration
    @Conditional(Auth0Condition.class)
    protected static class Auth0Configuration {

        @Inject
        private IxorTalkConfigProperties ixorTalkConfigProperties;

        @Bean
        public AudienceValidator audienceValidator() {
            return new AudienceValidator(ixorTalkConfigProperties.getAuth0().getAudience());
        }

        @Bean
        public OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient() {
            return createClientCredentialsTokenResponseClient(ixorTalkConfigProperties.getAuth0().getAudience());
        }

        private static OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> createClientCredentialsTokenResponseClient(String audience) {
            DefaultClientCredentialsTokenResponseClient clientCredentialsTokenResponseClient = new DefaultClientCredentialsTokenResponseClient();
            clientCredentialsTokenResponseClient.setRequestEntityConverter(new AudienceRequestEntityConverter<>(audience, new OAuth2ClientCredentialsGrantRequestEntityConverter()));
            return clientCredentialsTokenResponseClient;
        }

        private OAuth2AuthorizedClientProvider oAuth2AuthorizedClientProvider() {
            return builder()
                    .clientCredentials(configurer -> configurer.accessTokenResponseClient(clientCredentialsTokenResponseClient()))
                    .build();
        }

        @Bean
        public OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
                                                              OAuth2AuthorizedClientRepository authorizedClientRepository) {
            DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
            authorizedClientManager.setAuthorizedClientProvider(oAuth2AuthorizedClientProvider());
            return authorizedClientManager;
        }

        @Bean
        public AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientServiceOAuth2AuthorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
                                                                                                                              OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
            AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, oAuth2AuthorizedClientService);
            authorizedClientManager.setAuthorizedClientProvider(oAuth2AuthorizedClientProvider());
            return authorizedClientManager;
        }

        @Configuration
        protected static class Auth0ManagementAPIConfiguration {

            @Inject
            private IxorTalkConfigProperties ixorTalkConfigProperties;

            @Bean
            public Auth0ManagementAPI auth0ManagementAPI(AuthorizedClientServiceOAuth2AuthorizedClientManager auth0AuthorizedClientServiceOAuth2AuthorizedClientManager) {
                OAuth2AuthorizeRequest authorizeRequest =
                        withClientRegistrationId(ixorTalkConfigProperties.getAuth0().getManagementApi().getClientRegistrationId())
                                .principal(new AnonymousAuthenticationToken("auth0ManagementAPI", "auth0ManagementAPI", createAuthorityList("ROLE_ANONYMOUS")))
                                .build();

                return new Auth0ManagementAPI(ixorTalkConfigProperties.getAuth0().getDomain(), ixorTalkConfigProperties.getAuth0().getManagementApi().getCreateUserConnection(), auth0AuthorizedClientServiceOAuth2AuthorizedClientManager, authorizeRequest);
            }

            @Bean
            public AuthorizedClientServiceOAuth2AuthorizedClientManager auth0AuthorizedClientServiceOAuth2AuthorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
                                                                                                                      OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
                AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, oAuth2AuthorizedClientService);
                authorizedClientManager.setAuthorizedClientProvider(
                        builder()
                                .clientCredentials(configurer -> configurer.accessTokenResponseClient(createClientCredentialsTokenResponseClient(ixorTalkConfigProperties.getAuth0().getManagementApi().getAudience())))
                                .build());
                return authorizedClientManager;
            }

            @Bean
            public Auth0Users auth0Users(Auth0ManagementAPI auth0ManagementAPI) {
                return new Auth0Users(auth0ManagementAPI);
            }

            @Bean
            public Auth0Roles auth0Roles(Auth0ManagementAPI auth0ManagementAPI) {
                return new Auth0Roles(auth0ManagementAPI);
            }

            @Bean
            public Cache auth0UserByIdCache() {
                return new CaffeineCache(AUTH_0_USER_BY_ID_CACHE,
                        newBuilder()
                                .expireAfterWrite(ixorTalkConfigProperties.getAuth0().getManagementApi().getUserCache().getTimeToLiveInSeconds(), SECONDS)
                                .build());
            }

            @Bean
            public Cache auth0UserByEmailCache() {
                return new CaffeineCache(AUTH_0_USER_BY_EMAIL_CACHE,
                        newBuilder()
                                .expireAfterWrite(ixorTalkConfigProperties.getAuth0().getManagementApi().getUserCache().getTimeToLiveInSeconds(), SECONDS)
                                .build());
            }


            @Bean
            public Cache auth0RoleCache() {
                return new CaffeineCache(AUTH_0_ROLE_CACHE,
                        newBuilder()
                                .expireAfterWrite(ixorTalkConfigProperties.getAuth0().getManagementApi().getRolesCache().getTimeToLiveInSeconds(), SECONDS)
                                .build());
            }

            @Bean
            public Cache auth0UserRoleCache() {
                return new CaffeineCache(AUTH_0_USER_ROLE_CACHE,
                        newBuilder()
                                .expireAfterWrite(ixorTalkConfigProperties.getAuth0().getManagementApi().getUserRoleCache().getTimeToLiveInSeconds(), SECONDS)
                                .build());
            }

            @Bean
            public Cache auth0RoleUserCache() {
                return new CaffeineCache(AUTH_0_ROLE_USER_CACHE,
                        newBuilder()
                                .expireAfterWrite(ixorTalkConfigProperties.getAuth0().getManagementApi().getRoleUserCache().getTimeToLiveInSeconds(), SECONDS)
                                .build());
            }
        }
    }

    public static class Auth0Condition extends AllNestedConditions {

        public Auth0Condition() {
            super(ConfigurationPhase.PARSE_CONFIGURATION);
        }

        @ConditionalOnProperty(prefix = "ixortalk.auth0", name = "domain")
        static class AuthDomainConfigured {
        }
    }
}
