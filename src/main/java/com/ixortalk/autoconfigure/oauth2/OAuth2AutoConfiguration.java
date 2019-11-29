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

import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.spring.security.api.JwtWebSecurityConfigurer;
import com.auth0.spring.security.api.authentication.AuthenticationJsonWebToken;
import com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.Auth0AuthoritiesExtractor;
import com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.Auth0ManagementAPI;
import com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.Auth0Roles;
import com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.Auth0Users;
import com.ixortalk.autoconfigure.oauth2.claims.Auth0ClaimsProvider;
import com.ixortalk.autoconfigure.oauth2.claims.ClaimsProvider;
import com.ixortalk.autoconfigure.oauth2.claims.OAuth2ClaimsProvider;
import com.ixortalk.autoconfigure.oauth2.util.BearerTokenExtractor;
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.NoneNestedConditions;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerTokenServicesConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.Cache;
import org.springframework.cache.guava.GuavaCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import javax.inject.Inject;
import java.util.List;

import static com.google.common.cache.CacheBuilder.newBuilder;
import static com.ixortalk.autoconfigure.oauth2.OAuth2AutoConfiguration.IxorTalkWebSecurityConfigurerAdapter.DEFAULT_WEB_SECURITY_CONFIGURER_ADAPTER_ORDER;
import static com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.Auth0ManagementAPI.AUTH_0_ROLE_CACHE;
import static com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.Auth0ManagementAPI.AUTH_0_USER_CACHE;
import static com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.Auth0ManagementAPI.AUTH_0_USER_ROLE_CACHE;
import static java.lang.String.format;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.springframework.util.StringUtils.isEmpty;

@Configuration
@AutoConfigureAfter(ResourceServerTokenServicesConfiguration.class)
@EnableWebSecurity
public class OAuth2AutoConfiguration {

    @Configuration
    @EnableConfigurationProperties(IxorTalkAuth0ConfigProperties.class)
    @Conditional(Auth0Condition.class)
    protected static class Auth0Configuration implements IxorTalkHttpSecurityConfigurer {

        @Inject
        private IxorTalkAuth0ConfigProperties ixorTalkAuth0ConfigProperties;

        @Override
        public void configure(HttpSecurity http) throws Exception {
            JwtWebSecurityConfigurer
                    .forRS256(ixorTalkAuth0ConfigProperties.getAudience(), format("https://%s/", ixorTalkAuth0ConfigProperties.getDomain()))
                    .configure(http);
        }

        @Bean
        public BearerTokenExtractor auth0BearerTokenExtractor() {
            return () -> {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (authentication instanceof AuthenticationJsonWebToken) {
                    AuthenticationJsonWebToken authenticationJsonWebToken = (AuthenticationJsonWebToken) authentication;
                    return authenticationJsonWebToken.getToken();
                }

                throw new IllegalStateException("No bearer token present in security context");
            };
        }

        @Bean
        public ClaimsProvider auth0ClaimsProvider() {
            return new Auth0ClaimsProvider();
        }

        @Bean
        @ConditionalOnBean(ClientCredentialsResourceDetails.class)
        @Primary
        public OAuth2RestTemplate auth0ClientCredentialsOAuth2RestTemplate(ClientCredentialsResourceDetails clientCredentialsResourceDetails) {
            return createAuth0ClientCredentialsRestTemplate(clientCredentialsResourceDetails, ixorTalkAuth0ConfigProperties.getAudience());
        }

        static OAuth2RestTemplate createAuth0ClientCredentialsRestTemplate(ClientCredentialsResourceDetails clientCredentialsResourceDetails, String audience) {
            ClientCredentialsAccessTokenProvider clientCredentialsAccessTokenProvider = new ClientCredentialsAccessTokenProvider();
            clientCredentialsAccessTokenProvider.setTokenRequestEnhancer((request, resource, form, headers) -> form.set("audience", audience));

            OAuth2RestTemplate auth0OAuth2RestTemplate = new OAuth2RestTemplate(clientCredentialsResourceDetails);
            auth0OAuth2RestTemplate.setAccessTokenProvider(clientCredentialsAccessTokenProvider);
            return auth0OAuth2RestTemplate;
        }

        @Configuration
        protected static class Auth0ManagementAPIConfiguration {

            @Inject
            private IxorTalkAuth0ConfigProperties ixorTalkAuth0ConfigProperties;

            @Bean
            public ManagementAPI managementAPI() {
                return new ManagementAPI(ixorTalkAuth0ConfigProperties.getDomain(), auth0ManagementAPIRestTemplate().getAccessToken().getValue());
            }

            @Bean
            public Auth0ManagementAPI auth0ManagementAPI() {
                return new Auth0ManagementAPI(managementAPI(), auth0ManagementAPIRestTemplate(), ixorTalkAuth0ConfigProperties.getManagementApi().getCreateUserConnection());
            }

            @Bean
            public OAuth2RestTemplate auth0ManagementAPIRestTemplate() {
                ClientCredentialsResourceDetails managementAPIResource = new ClientCredentialsResourceDetails();
                managementAPIResource.setAccessTokenUri(format("https://%s/oauth/token", ixorTalkAuth0ConfigProperties.getDomain()));
                managementAPIResource.setClientId(ixorTalkAuth0ConfigProperties.getClientId());
                managementAPIResource.setClientSecret(ixorTalkAuth0ConfigProperties.getClientSecret());
                return createAuth0ClientCredentialsRestTemplate(managementAPIResource, ixorTalkAuth0ConfigProperties.getManagementApi().getAudience());
            }

            @Bean
            public Auth0Users auth0Users() {
                return new Auth0Users(auth0ManagementAPI());
            }

            @Bean
            public Auth0Roles auth0Roles() {
                return new Auth0Roles(auth0ManagementAPI());
            }

            @Bean
            @ConditionalOnBean(UserInfoTokenServices.class)
            public AuthoritiesExtractor auth0AuthoritiesExtractor() {
                return new Auth0AuthoritiesExtractor(managementAPI(), auth0ManagementAPIRestTemplate());
            }

            @Bean
            public Cache auth0UserCache() {
                return new GuavaCache(AUTH_0_USER_CACHE,
                        newBuilder()
                                .expireAfterWrite(ixorTalkAuth0ConfigProperties.getManagementApi().getUserCache().getTimeToLiveInSeconds(), SECONDS)
                                .build());
            }

            @Bean
            public Cache auth0RoleCache() {
                return new GuavaCache(AUTH_0_ROLE_CACHE,
                        newBuilder()
                                .expireAfterWrite(ixorTalkAuth0ConfigProperties.getManagementApi().getRolesCache().getTimeToLiveInSeconds(), SECONDS)
                                .build());
            }

            @Bean
            public Cache auth0UserRoleCache() {
                return new GuavaCache(AUTH_0_USER_ROLE_CACHE,
                        newBuilder()
                                .expireAfterWrite(ixorTalkAuth0ConfigProperties.getManagementApi().getUserRoleCache().getTimeToLiveInSeconds(), SECONDS)
                                .build());
            }
        }
    }

    @Configuration
    @Conditional(NoAuth0Condition.class)
    @ConditionalOnProperty(prefix = "ixortalk.oauth2.resource-server", name = "enabled", havingValue = "true", matchIfMissing = true)
    @Import({ResourceServerConfiguration.class, ResourceServerTokenServicesConfiguration.class})
    protected static class PlainOAuth2Configuration {

        @Bean
        public BearerTokenExtractor plainOAuth2BearerTokenExtractor() {
            return () -> {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (authentication instanceof OAuth2Authentication) {
                    OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authentication;
                    Object details = oAuth2Authentication.getDetails();
                    if (details instanceof OAuth2AuthenticationDetails) {
                        OAuth2AuthenticationDetails oAuth2AuthenticationDetails = (OAuth2AuthenticationDetails) details;
                        return oAuth2AuthenticationDetails.getTokenValue();
                    }
                }

                throw new IllegalStateException("No bearer token present in security context");
            };
        }

        @Bean
        @ConditionalOnBean(ClientCredentialsResourceDetails.class)
        public OAuth2RestTemplate plainOAuth2ClientCredentialsRestTemplate(ClientCredentialsResourceDetails clientCredentialsResourceDetails) {
            return new OAuth2RestTemplate(clientCredentialsResourceDetails);
        }

        @Bean
        @ConditionalOnBean(JwtAccessTokenConverter.class)
        public ClaimsProvider oAuth2ClaimsProvider() {
            return new OAuth2ClaimsProvider();
        }
    }

    @Configuration
    @ConditionalOnMissingBean(IxorTalkHttpSecurityConfigurer.class)
    public static class DefaultIxorTalkHttpSecurityConfigurerConfiguration {

        @Bean
        public IxorTalkHttpSecurityConfigurer defaultIxorTalkHttpSecurityConfigurer() {
            return http -> http.authorizeRequests().anyRequest().authenticated();
        }
    }

    @Configuration
    @Order(DEFAULT_WEB_SECURITY_CONFIGURER_ADAPTER_ORDER + 1)
    protected static class IxorTalkWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements ResourceServerConfigurer {

        public static final int DEFAULT_WEB_SECURITY_CONFIGURER_ADAPTER_ORDER = 100;

        @Inject
        private ManagementServerProperties managementServerProperties;

        @Inject
        private List<IxorTalkHttpSecurityConfigurer> ixorTalkHttpSecurityConfigurers;

        @Override
        public void configure(WebSecurity web) {
            if (!isEmpty(managementServerProperties.getContextPath())) {
                web.ignoring().antMatchers(managementServerProperties.getContextPath() + "/**");
            }
        }

        @Override
        public void configure(ResourceServerSecurityConfigurer resources) throws Exception {

        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            for (IxorTalkHttpSecurityConfigurer ixorTalkHttpSecurityConfigurer : ixorTalkHttpSecurityConfigurers) {
                ixorTalkHttpSecurityConfigurer.configure(http);
            }
        }
    }

    public static class NoAuth0Condition extends NoneNestedConditions {

        NoAuth0Condition() {
            super(ConfigurationPhase.PARSE_CONFIGURATION);
        }

        @Conditional(Auth0Condition.class)
        static class Auth0ConditionMatched {

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
