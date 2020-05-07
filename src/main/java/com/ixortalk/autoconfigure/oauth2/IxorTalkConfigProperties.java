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

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("ixortalk")
public class IxorTalkConfigProperties {

    private Security security = new Security();

    private Auth0 auth0 = new Auth0();

    public Security getSecurity() {
        return security;
    }

    public Auth0 getAuth0() {
        return auth0;
    }

    public static class Security {

        private Jwt jwt = new Jwt();

        private Feign feign = new Feign();

        public Jwt getJwt() {
            return jwt;
        }

        public Feign getFeign() {
            return feign;
        }
    }

    public static class Jwt {

        private String authoritiesClaimName = "scope";

        public String getAuthoritiesClaimName() {
            return authoritiesClaimName;
        }

        public void setAuthoritiesClaimName(String authoritiesClaimName) {
            this.authoritiesClaimName = authoritiesClaimName;
        }
    }

    public static class Feign {

        private String serviceToServiceClientRegistrationId;

        public String getServiceToServiceClientRegistrationId() {
            return serviceToServiceClientRegistrationId;
        }

        public void setServiceToServiceClientRegistrationId(String serviceToServiceClientRegistrationId) {
            this.serviceToServiceClientRegistrationId = serviceToServiceClientRegistrationId;
        }
    }

    public static class Auth0 {

        private String domain;
        private String audience;
        private String clientId;
        private String clientSecret;

        private ManagementApi managementApi = new ManagementApi();

        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public ManagementApi getManagementApi() {
            return managementApi;
        }
    }

    public static class ManagementApi {

        private String audience;
        private String clientRegistrationId;
        private Cache userCache = new Cache();
        private Cache rolesCache = new Cache();
        private Cache userRoleCache = new Cache();

        private String createUserConnection = "Username-Password-Authentication";

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getClientRegistrationId() {
            return clientRegistrationId;
        }

        public void setClientRegistrationId(String clientRegistrationId) {
            this.clientRegistrationId = clientRegistrationId;
        }

        public Cache getUserCache() {
            return userCache;
        }

        public Cache getRolesCache() {
            return rolesCache;
        }

        public Cache getUserRoleCache() {
            return userRoleCache;
        }

        public String getCreateUserConnection() {
            return createUserConnection;
        }

        public void setCreateUserConnection(String createUserConnection) {
            this.createUserConnection = createUserConnection;
        }
    }

    public static class Cache {

        private int timeToLiveInSeconds = 2;

        public int getTimeToLiveInSeconds() {
            return timeToLiveInSeconds;
        }

        public void setTimeToLiveInSeconds(int timeToLiveInSeconds) {
            this.timeToLiveInSeconds = timeToLiveInSeconds;
        }
    }
}
