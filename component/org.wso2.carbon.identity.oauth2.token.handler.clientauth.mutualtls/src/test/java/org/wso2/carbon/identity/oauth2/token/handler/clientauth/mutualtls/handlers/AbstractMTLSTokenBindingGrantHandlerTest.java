/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.handlers;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.CommonConstants;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;
import org.wso2.carbon.utils.CarbonUtils;

import java.util.ArrayList;

import static org.mockito.ArgumentMatchers.any;
import static org.testng.Assert.assertFalse;
/**
 * Test class for AbstractMTLSTokenBindingGrantHandlerTest class.
 */
@PrepareForTest({IdentityUtil.class, CarbonUtils.class, Oauth2ScopeUtils.class, OAuth2Util.class})

@WithCarbonHome
public class AbstractMTLSTokenBindingGrantHandlerTest {

    private static final Logger log = LoggerFactory.getLogger(AbstractMTLSTokenBindingGrantHandlerTest.class);
    MTLSTokenBindingAuthorizationCodeGrantHandler mtlsTokenBindingAuthorizationCodeGrantHandler;

    private static String CERTIFICATE_CONTENT = "-----BEGIN CERTIFICATE-----MIID3TCCAsWgAwIBAgIUJQW8iwYsAbyjc/oHti" +
            "8DPLJH5ZcwDQYJKoZIhvcNAQELBQAwfjELMAkGA1UEBhMCU0wxEDAOBgNVBAgMB1dlc3Rlcm4xEDAOBgNVBAcMB0NvbG9tYm8xDTA" +
            "LBgNVBAoMBFdTTzIxDDAKBgNVBAsMA0lBTTENMAsGA1UEAwwER2FnYTEfMB0GCSqGSIb3DQEJARYQZ2FuZ2FuaUB3c28yLmNvbTAe" +
            "Fw0yMDAzMjQxMjQyMDFaFw0zMDAzMjIxMjQyMDFaMH4xCzAJBgNVBAYTAlNMMRAwDgYDVQQIDAdXZXN0ZXJuMRAwDgYDVQQHDAdDb" +
            "2xvbWJvMQ0wCwYDVQQKDARXU08yMQwwCgYDVQQLDANJQU0xDTALBgNVBAMMBEdhZ2ExHzAdBgkqhkiG9w0BCQEWEGdhbmdhbmlAd3" +
            "NvMi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+reCEYOn2lnWgFsp0TF0R1wQiD9C/N+dnv4xCa0rFiu4njDz" +
            "WR/8tYFl0koaxXoP0+oGnT07KlkA66q0ztwikLZXphLdCBbJ1hSmNvor48FuSb6DgqWixrUa2LHlpaaV7RvlmG+IhZEgKDXdS+/tK" +
            "0hlcgRzENyOEdETDO5fFlKGGuwaGv6/w69h2LTKGu5nyDLF51rjQ18xp026btHC7se/XSlcp3X63xeOIcFv6m84AN2lnV+g8MOfu2" +
            "wgWtsKaxn4BL64E7nHZNNLxMRf7GtUm2bl9ydFX4aD1r1Oj4iqFWMNcfQ676Qshk8s7ui3LKWFXwNN/SRD0c/ORtv23AgMBAAGjUz" +
            "BRMB0GA1UdDgQWBBRDu/vqRafReh4fFHS3Nz4T6u9mUDAfBgNVHSMEGDAWgBRDu/vqRafReh4fFHS3Nz4T6u9mUDAPBgNVHRMBAf8" +
            "EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB7NH51Yj4moEhMonnLUh3eTtf6DUnrpscx6td28rryoDZPfCkJs4VHU9F50etw54Fo" +
            "HqoIaHp5UIB6l1OsVXytUmwrdxbqW7nfOItYwN1yV093aI2aOeMQYmS+vrPkSkxySP6+wGCWe4gfMgpr6iu9xiWLpnILw5q71gmXW" +
            "tS900S5aLbllGYe74jkyldLIdhS4TyEBIDgcpZrD8x/Z42al6T/6EANMpvu4Jopisg+uwwkEGSM1I/kjiW+YkWC4oTZ1jMZUWC11W" +
            "bcouLwjfaf6gt4zWitYCP0r0fLGk4bSJfUFsnJNu6vDhx60TbRhIh9P2jxkmgNYPuAxFtF8v+h-----END CERTIFICATE-----";

    private static OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTOObject() {

        OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oauth2AccessTokenReqDTO.setHttpRequestHeaders(getHttpRequestHeaders
                (new String[]{"content-type", "x-wso2-mutual-auth-cert", "user-agent"},
                        new String[]{"application/x-www-form-urlencoded", CERTIFICATE_CONTENT,
                                "PostmanRuntime/7.24.0"}));
        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.addParameter(CommonConstants.AUTHENTICATOR_TYPE_PARAM,
                CommonConstants.AUTHENTICATOR_TYPE_MTLS);
        oauth2AccessTokenReqDTO.setoAuthClientAuthnContext(oAuthClientAuthnContext);
        oauth2AccessTokenReqDTO.setGrantType("Bearer");
        return oauth2AccessTokenReqDTO;
    }

    private static HttpRequestHeader[] getHttpRequestHeaders(String[] key, String[] value) {

        ArrayList<HttpRequestHeader> httpRequestHeaders = new ArrayList<>();

        for (int count = 0; count < key.length; count++) {
            httpRequestHeaders.add(new HttpRequestHeader(key[count], value[count]));
        }
        return httpRequestHeaders.toArray(new HttpRequestHeader[0]);
    }

    @Test
    public void testValidateScope() {

        try {
            MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class);
            identityUtil.when(() ->  IdentityUtil.getProperty(CommonConstants.MTLS_AUTH_HEADER)).thenReturn("x-wso2-mutual-auth-cert");
            identityUtil.when(() -> IdentityUtil.getIdentityConfigDirPath()).thenReturn(System.
                    getProperty("user.dir") + "/src/test/resources/repository/conf/identity");

            mtlsTokenBindingAuthorizationCodeGrantHandler = new MTLSTokenBindingAuthorizationCodeGrantHandler();

            MockedStatic<Oauth2ScopeUtils> oauth2ScopeUtils = Mockito.mockStatic(Oauth2ScopeUtils.class);
            oauth2ScopeUtils.when(() -> Oauth2ScopeUtils.validateByApplicationScopeValidator(any(OAuthTokenReqMessageContext.class),
                    any(OAuthAuthzReqMessageContext.class))).thenReturn(false);

            OAuthTokenReqMessageContext oAuthTokenReqMessageContext =
                    new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTOObject());
            oAuthTokenReqMessageContext.setScope(new String[]{"openid"});

            boolean validateScope =
                    mtlsTokenBindingAuthorizationCodeGrantHandler.validateScope(oAuthTokenReqMessageContext);
            assertFalse(validateScope);

        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
        }
    }
}
