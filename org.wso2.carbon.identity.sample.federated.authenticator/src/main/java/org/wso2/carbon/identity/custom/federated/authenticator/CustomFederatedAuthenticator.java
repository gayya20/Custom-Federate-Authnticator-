/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.custom.federated.authenticator;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.cookie.Cookie;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.custom.federated.authenticator.internal.BasicAuth;
import org.wso2.carbon.identity.custom.federated.authenticator.internal.UserRegistrationComponent;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.constants.UserCoreClaimConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;


import java.io.IOException;
import java.net.URLEncoder;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.PASSWORD_PROPERTY;

public class CustomFederatedAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {
    private static final String USER_NAME = "username";
    private static final String PASSWORD = "password";

    private String getUserName(HttpServletRequest request) {
        return request.getParameter(USER_NAME);
    }

    // Method to retrieve password from request
    private String getPassword(HttpServletRequest request) {
        return request.getParameter(PASSWORD);
    }


    private static final Log log = LogFactory.getLog(CustomFederatedAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String userName = request.getParameter(USER_NAME);
        String password = request.getParameter(PASSWORD);

        return (userName != null && password != null);
    }

    @Override
    public String getFriendlyName() {

        return "custom-federated-authenticator";
    }

    @Override
    public String getName() {

        return "CustomFederatedAuthenticator";
    }

    @Override
    public String getClaimDialectURI() {

        // Get the claim dialect URI if this authenticator receives claims in a standard dialect.
        return CustomFederatedAuthenticatorConstants.OIDC_DIALECT;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        // Get the required configuration properties.
        List<Property> configProperties = new ArrayList<>();
        Property clientId = new Property();
        clientId.setName(CustomFederatedAuthenticatorConstants.API_URL);
        clientId.setDisplayName("API Endpoint URL");
        clientId.setRequired(true);
        clientId.setDescription("Enter Secondary SERVER endpoint url");
        clientId.setType("string");
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property contentType = new Property();
        contentType.setName(CustomFederatedAuthenticatorConstants.CONTENT_TYPE);
        contentType.setDisplayName("Content-Type");
        contentType.setDescription("The content type of the request body");
        contentType.setRequired(true);
        contentType.setType("string");
        contentType.setDisplayOrder(2);
        configProperties.add(contentType);

        Property acceptHeader = new Property();
        acceptHeader.setName(CustomFederatedAuthenticatorConstants.ACCEPT_HEADER);
        acceptHeader.setDisplayName("Accept");
        acceptHeader.setDescription("The expected content type of the response");
        acceptHeader.setRequired(true);
        acceptHeader.setType("string");
        acceptHeader.setDisplayOrder(3);
        configProperties.add(acceptHeader);

        Property jsonTemplate = new Property();
        jsonTemplate.setName(CustomFederatedAuthenticatorConstants.JSON_TEMPLATE);
        jsonTemplate.setDisplayName("JSON Template");
        jsonTemplate.setRequired(true);
        jsonTemplate.setDescription("Enter the JSON template for the request body. Use {$username} and {$password} as placeholders.");
        jsonTemplate.setDescription("Ex: {\"username\": \"{$username}\", \"password\": \"{$password}\"}");
        jsonTemplate.setType("string");
        jsonTemplate.setDisplayOrder(6);
        configProperties.add(jsonTemplate);


        return configProperties;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            // Initiate authentication request to redirect to login page.
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties != null) {
            } else {
                throw new AuthenticationFailedException("Error while retrieving properties. " +
                        "Authenticator Properties cannot be null");
            }
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
            String authenticators = authenticatorProperties.get("authenticators");

            FrameworkConstants.LogConstants BasicAuthenticatorConstants = new FrameworkConstants.LogConstants();
            String redirectURL = loginPage + "?" + queryParams +"&authenticators=BasicAuthenticator%3ALOCAL" ;



            response.sendRedirect(redirectURL);

        } catch (IOException e) {
            throw new AuthenticationFailedException("Exception while building authorization code request", e);
        }

    }





    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        String username = getUserName(request);
        String password = getPassword(request);

        // Log for debugging
        if (username == null || password == null) {
            log.error("Username or Password is null");
            throw new AuthenticationFailedException("Username or Password is null");
        }

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String apiUrl = authenticatorProperties.get(CustomFederatedAuthenticatorConstants.API_URL);


        String requestTenantDomain = MultitenantUtils.getTenantDomain(username);


        boolean isAuthenticated = authenticateViaBasicAuth(username, password);
        //Authenticate with IS1



        if(isAuthenticated){
            System.out.println("Authentication successful!");

        }

        else {//Authenticate with IS 2


            HttpPostRequest httpPostRequest = new HttpPostRequest(apiUrl,context);
            boolean isPostSuccess = false;

            try {
                isPostSuccess = httpPostRequest.sendPostRequest(username, password,context);
            } catch (IOException e) {
                log.error("Exception while sending POST request to API", e);
                throw new AuthenticationFailedException("Exception while sending POST request to API", e);
            }


            if (isPostSuccess) {
                System.out.println("Authentication successful!");
                try {
                    UserRegistrationComponent.registerUser(username, password);
                } catch (UserStoreException e) {
                    throw new RuntimeException(e);
                }
            } else {
                System.out.println("Authentication failed!"); // Print error message
                throw new AuthenticationFailedException("Authentication failed");

            }



            try {
                // Simulate success authentication process, set authenticated user
                AuthenticatedUser authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(username);
                context.setSubject(authenticatedUser);
            } catch (Exception e) {
                log.error("Authentication process failed", e);
                throw new AuthenticationFailedException("Authentication process failed", e);
            }
        }

        try {
            AuthenticatedUser authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(username);
            context.setSubject(authenticatedUser);
        } catch (Exception e) {
            log.error("Error while setting authenticated user in context", e);
            throw new AuthenticationFailedException("Error while setting authenticated user in context", e);
        }
    }

    private boolean authenticateViaBasicAuth(String username, String password) {
        BasicAuth basicAuth = new BasicAuth();
        return basicAuth.authenticate(username, password);
    }


    private boolean authenticateViaIS2(String username, String password) {
        return true;

    }

    private boolean authenticateLocally(String username, String password) {
        boolean isAuthenticated = false;

        return true; // Replace with actual implementation

    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        String state = request.getParameter(CustomFederatedAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[0];
        } else {
            return null;
        }
    }

    private String getAuthenticateUser(Map<String, Object> oidcClaims) {

        // Get the authenticated user's user Id from the id_token by the sub claim value.
        return (String) oidcClaims.get(CustomFederatedAuthenticatorConstants.SUB);
    }

    private Map<String, Object> getIdTokenClaims(AuthenticationContext context, String idToken) {

        context.setProperty(CustomFederatedAuthenticatorConstants.ID_TOKEN, idToken);
        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = JSONObjectUtils.parseJSONObject(new String(decoded)).entrySet();
        } catch (ParseException e) {
            log.error("Error occurred while parsing JWT provided by federated IDP: ", e);
        }
        Map<String, Object> jwtAttributeMap = new HashMap();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
        }
        return jwtAttributeMap;
    }

    private OAuthClientRequest getAccessTokenRequest(AuthenticationContext context, OAuthAuthzResponse
            authzResponse) throws AuthenticationFailedException {

        // Extract the authentication properties from the context.
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String clientId = authenticatorProperties.get(CustomFederatedAuthenticatorConstants.CLIENT_ID);
        String clientSecret = authenticatorProperties.get(CustomFederatedAuthenticatorConstants.CLIENT_SECRET);
        String tokenEndPoint = authenticatorProperties.get(CustomFederatedAuthenticatorConstants.OAUTH2_TOKEN_URL);
        String callbackUrl = authenticatorProperties.get(CustomFederatedAuthenticatorConstants.CALLBACK_URL);

        OAuthClientRequest accessTokenRequest;
        try {
            // Build access token request
            accessTokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint).setGrantType(GrantType
                    .AUTHORIZATION_CODE).setClientId(clientId).setClientSecret(clientSecret).setRedirectURI
                    (callbackUrl).setCode(authzResponse.getCode()).buildBodyMessage();
            if (accessTokenRequest != null) {
                String serviceUrl = IdentityUtil.getServicePath();
                String serverURL = IdentityUtil.getServerURL(serviceUrl, true, true);
                accessTokenRequest.addHeader(CustomFederatedAuthenticatorConstants.HTTP_ORIGIN_HEADER, serverURL);
            }
        } catch (OAuthSystemException e) {
            throw new AuthenticationFailedException("Error while building access token request", e);
        }
        return accessTokenRequest;
    }

    private OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws AuthenticationFailedException {

        OAuthClientResponse oAuthResponse;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            throw new AuthenticationFailedException("Exception while requesting access token");
        }
        return oAuthResponse;
    }

    private String getLoginType(HttpServletRequest request) {

        String state = request.getParameter(CustomFederatedAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            String[] stateElements = state.split(",");
            if (stateElements.length > 1) {
                return stateElements[1];
            }
        }
        return null;
    }
}
