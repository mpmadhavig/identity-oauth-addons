/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.model.ClientAuthenticationMethodModel;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.CommonConstants;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.MutualTLSUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.MutualTLSUtil.JAVAX_SERVLET_REQUEST_CERTIFICATE;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

@WithCarbonHome
@PrepareForTest({OAuth2Util.class, HttpServletRequest.class, MutualTLSUtil.class, IdentityUtil.class})
public class MutualTLSClientAuthenticatorTest extends PowerMockTestCase {

    private MutualTLSClientAuthenticator mutualTLSClientAuthenticator = new MutualTLSClientAuthenticator();
    private static String CLIENT_ID = "someclientid";
    private static String CERTIFICATE_CONTENT =
            "MIIDmzCCAoOgAwIBAgIJAJuzH6NrV5s5MA0GCSqGSIb3DQEBCwUAMGQxCzAJBgNV" +
            "BAYTAlNMMQswCQYDVQQIDAJXUDEQMA4GA1UEBwwHQ29sb21ibzENMAsGA1UECgwE\n" +
            "d3NvMjENMAsGA1UECwwEd3NvMjEYMBYGA1UEAwwPdHJhdmVsb2NpdHkuY29tMB4X\n" +
            "DTE4MDIwNjEwNTk1N1oXDTE5MDIwNjEwNTk1N1owZDELMAkGA1UEBhMCU0wxCzAJ\n" +
            "BgNVBAgMAldQMRAwDgYDVQQHDAdDb2xvbWJvMQ0wCwYDVQQKDAR3c28yMQ0wCwYD\n" +
            "VQQLDAR3c28yMRgwFgYDVQQDDA90cmF2ZWxvY2l0eS5jb20wggEiMA0GCSqGSIb3\n" +
            "DQEBAQUAA4IBDwAwggEKAoIBAQDlKn3dmaLW7iBOKdlWY8Go8Q7kR6HNY/8j0arv\n" +
            "EcZYqMrihcSX5i5Mz57t6Z3xpaGay2jPWND7dDA/RocircleBKQk0X2OxoEYba3W\n" +
            "t477EpN9RWGAZuuANUSVKjC8FsNYhEp9y59IuxK+IgDAEfR8O2RNLYA6O3UjBC/R\n" +
            "f443CwOE4jFm3eVAeLIBudn/viC56rPBozVX4DxPaHIzxocfK6EpDljEG4lJ7otS\n" +
            "SbIpPlmAO/0f8F1Q6syv+sCkPRGn/OjTXWtUg6QXAclguOCl3MI+pLMThQUATcKb\n" +
            "2QkPl8r8/b/S8qMRKzSVYyjNP+CsDRO/MdlC50QZSJBaNYqdAgMBAAGjUDBOMB0G\n" +
            "A1UdDgQWBBSIXyhWV6Ac+FiqdXEeQwqzJfFLhDAfBgNVHSMEGDAWgBSIXyhWV6Ac\n" +
            "+FiqdXEeQwqzJfFLhDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBQ\n" +
            "S2jmfzF8x1iwmRqXILZ6qkF5ABAlNa3Z3bMFB7uErw2BxASMOLWfjZdEcyICDGIf\n" +
            "ZeYchqEPTvv/RIqDlu8xda3N2kRp1un5Hfffavm6ZWR3J8LdsnSjrehZ/afxuy8a\n" +
            "OFKiRtj9tqpG3C/s/NBJ9Gl4u5YhihOSJG9ELihJSxWDYI641AOalWnUQ/SxfeCO\n" +
            "TY75aViCAD6QDmBxe/opQYExBdgNOCQ6HdP5WWBT6EEggBe/mqOM/dchj57rpPtw\n" +
            "IOQjy9UCaY7tq4SmhAJyab0mxjcFoRBpzOJIDh+N8ozSDK+MepyFSwtW5zVacOiG\n" +
            "OQUrBTGXQFZOGKje8sbS";
    private static String  CERTIFICATE_CONTENT_2 =
            "MIIDpjCCAo4CCQDKBQ7NfoPWojANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMC\n"
            + "U0wxEDAOBgNVBAgMB1dlc3Rlcm4xEDAOBgNVBAcMB0NvbG9tYm8xDTALBgNVBAoM\n"
            + "BFdTTzIxCzAJBgNVBAsMAldBMRcwFQYDVQQDDA53c28yaXNAYWJjLmNvbTEsMCoG\n"
            + "CSqGSIb3DQEJARYdYnVkZGhpbWF1ZGFyYW5nYTEyM0BnbWFpbC5jb20wHhcNMTkw\n"
            + "NDAzMDYzMjAyWhcNMjAwNDAyMDYzMjAyWjCBlDELMAkGA1UEBhMCU0wxEDAOBgNV\n"
            + "BAgMB1dlc3Rlcm4xEDAOBgNVBAcMB0NvbG9tYm8xDTALBgNVBAoMBFdTTzIxCzAJ\n"
            + "BgNVBAsMAldBMRcwFQYDVQQDDA53c28yaXNAYWJjLmNvbTEsMCoGCSqGSIb3DQEJ\n"
            + "ARYdYnVkZGhpbWF1ZGFyYW5nYTEyM0BnbWFpbC5jb20wggEiMA0GCSqGSIb3DQEB\n"
            + "AQUAA4IBDwAwggEKAoIBAQDbvyzlB2FbWrs6utsPPfUAkX478lFnvJ4Dkw0wQY+Y\n"
            + "ucf2VV7nlfNZkRPssvczuRTo9Xf7DrSdCy8Lwk/hFndQnl6ugHBuijF/lnCUXcMz\n"
            + "EamobmNOM4PNaNp4juah7Gn89Kvw7AkXWem41QfVr0HkbUO9iLamE3r2jUf42CLS\n"
            + "F+NWVJv5FKRmM5oHf/oiiB4MfF6AgH0Reh4ptwMri0auUR8DoS7WR7KHuBIIZ/ZH\n"
            + "YliBQ6lZyCL+V854rB2SmwTiT2ee3j2BeUHJwdZTznkass4YOhUzu3eartLH8hqb\n"
            + "/W+hI7++Muv6JWt6JggOfpRABgljgh5SKGH/lJOvl1qNAgMBAAEwDQYJKoZIhvcN\n"
            + "AQELBQADggEBAE+iUq6/mHzwBMtmF5JHTLpXkunyAlbl4RRLQ1vg91Ei34T0TPus\n"
            + "zw/jB1ta5ShtchJzmaSEkVEHA1ZwaG8mqZ+JohsY1Z9vb2hevbC/V3H7sLqpCPZK\n"
            + "KCkaTp3buoHPPV3vAGLIsQrhRqVkulNiKJPGyz85R8bfrB36yk7PxSe0U9xy7Knr\n"
            + "vmO/dYUXGrprjfL7BaCq1eLw9Mx68anuhFYRspmdxoRGidJ6sm/I1ZD5oQEKa1tS\n"
            + "O6eaZWIa6CJF2/e4TMtEPeVEgWqtpLxYzhX2kEgzEXapxMkPwXPfym4I0b2Y0Ag/\n"
            + "7Kun3EsBCgp4r4S9zWAyLA1aJIo63OPDb9Q=";

    private static String CERTIFICATE_CONTENT3 = "-----BEGIN CERTIFICATE-----MIID3" +
            "TCCAsWgAwIBAgIUJQW8iwYsAbyjc/oHti8DPLJH5ZcwDQYJKoZIhvcNAQELBQAwfjELMA" +
            "kGA1UEBhMCU0wxEDAOBgNVBAgMB1dlc3Rlcm4xEDAOBgNVBAcMB0NvbG9tYm8xDTALBgN" +
            "VBAoMBFdTTzIxDDAKBgNVBAsMA0lBTTENMAsGA1UEAwwER2FnYTEfMB0GCSqGSIb3DQEJ" +
            "ARYQZ2FuZ2FuaUB3c28yLmNvbTAeFw0yMDAzMjQxMjQyMDFaFw0zMDAzMjIxMjQyMDFaM" +
            "H4xCzAJBgNVBAYTAlNMMRAwDgYDVQQIDAdXZXN0ZXJuMRAwDgYDVQQHDAdDb2xvbWJvMQ" +
            "0wCwYDVQQKDARXU08yMQwwCgYDVQQLDANJQU0xDTALBgNVBAMMBEdhZ2ExHzAdBgkqhki" +
            "G9w0BCQEWEGdhbmdhbmlAd3NvMi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK" +
            "AoIBAQC+reCEYOn2lnWgFsp0TF0R1wQiD9C/N+dnv4xCa0rFiu4njDzWR/8tYFl0koaxX" +
            "oP0+oGnT07KlkA66q0ztwikLZXphLdCBbJ1hSmNvor48FuSb6DgqWixrUa2LHlpaaV7Rv" +
            "lmG+IhZEgKDXdS+/tK0hlcgRzENyOEdETDO5fFlKGGuwaGv6/w69h2LTKGu5nyDLF51rj" +
            "Q18xp026btHC7se/XSlcp3X63xeOIcFv6m84AN2lnV+g8MOfu2wgWtsKaxn4BL64E7nHZ" +
            "NNLxMRf7GtUm2bl9ydFX4aD1r1Oj4iqFWMNcfQ676Qshk8s7ui3LKWFXwNN/SRD0c/ORt" +
            "v23AgMBAAGjUzBRMB0GA1UdDgQWBBRDu/vqRafReh4fFHS3Nz4T6u9mUDAfBgNVHSMEGD" +
            "AWgBRDu/vqRafReh4fFHS3Nz4T6u9mUDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQE" +
            "BCwUAA4IBAQB7NH51Yj4moEhMonnLUh3eTtf6DUnrpscx6td28rryoDZPfCkJs4VHU9F5" +
            "0etw54FoHqoIaHp5UIB6l1OsVXytUmwrdxbqW7nfOItYwN1yV093aI2aOeMQYmS+vrPkS" +
            "kxySP6+wGCWe4gfMgpr6iu9xiWLpnILw5q71gmXWtS900S5aLbllGYe74jkyldLIdhS4T" +
            "yEBIDgcpZrD8x/Z42al6T/6EANMpvu4Jopisg+uwwkEGSM1I/kjiW+YkWC4oTZ1jMZUWC" +
            "11WbcouLwjfaf6gt4zWitYCP0r0fLGk4bSJfUFsnJNu6vDhx60TbRhIh9P2jxkmgNYPuA" +
            "xFtF8v+h-----END CERTIFICATE-----";

    private static String TEST_JSON_WITH_X5T ="{\n" +
            "  \"keys\" : [ {\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"kid\" : \"RjM3REY1MEVFMUQ2MTZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"xd_gJKFwSqB0XbB8mq15S7Sv5WnZyQFHjFZBDLEpUHJV5UaGIVl652LP-TERvjk7gF16c8UCVT7G4xtzWw1hJtc1eDB5v6NsxpWRr5j2F6VdRvN__wuRRglmN1Gdw039ZvEGdCt-SEnVn4dpVuQ\",\n" +
            "    \"use\" : \"tls\",\n" +
            "    \"x5t\" : \"RjM3REY1MEVFMUQ2MTZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ\",\n" +
            "    \"x5u\" : \"https://keystore.abc.org.lk/RjM3REY1MEVFMUQ2MTZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ.pem\",\n" +
            "    \"x5t#S256\" : \"tpqKoJfFLhDAfBgNVHSM=\"\n" +
            "  }, {\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"kid\" : \"M2maFm3VYlMBOn3GetVWGXkrKrk\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"p_-g1hFttbORNAH9dJF0fbwdeJclG3rKuJDzLF80rIV88cFY1Iug_kRerjlSD5yQ5bJfNeP-V7XKILo570RR7GThgLwmWNWAWKA-63zmjr1OAI2IDx5R6krlY6dPQ57euwhMS8TWpuo27CHUirKAoBzPywcssPcpfRaT0dNv_83AkxRtsOUMizAWVh8MGhUUe2bHpQdRxKD_0X7U_5V3Y0aPFUikICTW2_Je8jbQ\",\n" +
            "    \"use\" : \"sig\",\n" +
            "    \"x5t\" : \"da39a3ee5e6b4b0d3255bfef95601890afd80709\",\n" +
            "    \"x5u\" : \"https://keystore.abc.org.lk/M2maFm3VYlMBOn3GetVWGXkrKrk.pem\",\n" +
            "    \"x5t#S256\" : \"M2maFm3VYlMBOn3GetVWGXkrKrk\"\n" +
            "  } ]\n" +
            "}";

    private static String TEST_JSON_WITH_X5C ="{\n" +
            "  \"keys\" : [ {\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"kid\" : \"RjM3REY1MEVFMUQ2MTZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"x_AfraZx04boy30iEHUAupKqq4hnjE4APFj1pLrs55QGDoTgSuTRw2xIzMSVjcUREM-UZFBlOXduL2B1SiYQdT8ctprJRZPvOkYZyUoYLPg9n1pEp_CVYeYhV71gLUmCmrUe52LP-TERvjk7gF16c8UCVT7G4xtzWw1hJtc1eDB5v6NsxpWRr5j2F6VdRvN__wuRRglmN1Gdw039ZvEGdCt-SEnVn4dpVuQ\",\n" +
            "    \"use\" : \"tls\",\n" +
            "    \"x5c\" : [ "
            + "\"MIIFODCCBCCgAwIBAgIEWcVdrDANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJHQjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxLjAsBgNVBAMTJU9wZW5CYW5raW5nIFByZS1Qcm9kdWN0aW9uIElzc3VpbmcgQ0EwHhcNMTgxMjA1MDMwMjU4WhcNMjAwMTA1MDMzMjU4WjBhMQswCQYDVQQGEwJHQjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxGzAZBgNVBAsTEjAwMTU4MDAwMDFIUVFyWkFBWDEfMB0GA1UEAxMWMlgwMXRUTEQwaEJtd2pFZ1dWakd2ajCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMfwH62mcdOG6Mt17Yu6D1zBItemYl1iIhcunIv76UChKhl7WyivNouvGWhww+hLxK0fAwnOkGsCuQBnf4CShcEqgdF2wfJqteUu0r+Vp2ckBR4xWQQyxKVByVeVGhiFZetIhB1ALqSqquIZ4xOADxY9aS67OeUBg6E4Erk0cNsSMzElY3FERDPlGRQZTl3bi9gdUomEHU/HLaayUWT7zpGGclKGCz4PZ9aRKfwlWHmIVe9YC1Jgpq1Hudiz/kxEb45O4BdenPFAlU+xuMbc1sNYSbXNXgweb+jbMaVka+Y9helXUbzf/8LkUYJZjdRncNN/WbxBnQrfkhJ1Z+HaVbkCAwEAAaOCAgQwggIAMA4GA1UdDwEB/wQEAwIHgDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwgeAGA1UdIASB2DCB1TCB0gYLKwYBBAGodYEGAWQwgcIwKgYIKwYBBQUHAgEWHmh0dHA6Ly9vYi50cnVzdGlzLmNvbS9wb2xpY2llczCBkwYIKwYBBQUHAgIwgYYMgYNVc2Ugb2YgdGhpcyBDZXJ0aWZpY2F0ZSBjb25zdGl0dXRlcyBhY2NlcHRhbmNlIG9mIHRoZSBPcGVuQmFua2luZyBSb290IENBIENlcnRpZmljYXRpb24gUG9saWNpZXMgYW5kIENlcnRpZmljYXRlIFByYWN0aWNlIFN0YXRlbWVudDBtBggrBgEFBQcBAQRhMF8wJgYIKwYBBQUHMAGGGmh0dHA6Ly9vYi50cnVzdGlzLmNvbS9vY3NwMDUGCCsGAQUFBzAChilodHRwOi8vb2IudHJ1c3Rpcy5jb20vb2JfcHBfaXNzdWluZ2NhLmNydDA6BgNVHR8EMzAxMC+gLaArhilodHRwOi8vb2IudHJ1c3Rpcy5jb20vb2JfcHBfaXNzdWluZ2NhLmNybDAfBgNVHSMEGDAWgBRQc5HGIXLTd/T+ABIGgVx5eW4/UDAdBgNVHQ4EFgQUwA+9otHiTEen8wHnnuitXR3ZuFowDQYJKoZIhvcNAQELBQADggEBADvRik60g4F43y8YMof/Ukle3pMuRUQlIe+Nk5LXbwcOI5iMZ0h768LbmqZRqN/yRUcvAeZFXE92O59iDWbVm2zTKvGaQaUwowvi9JuH2CTLQfW5+shmvEyJnRqf2mCpJWyh4W0JgckZwtljSYR0AsNnbjNhTE86MyaRZ1Uuun2fbNfQskKHb3bkPJcRkMfplGN5Y/uNFwnanfGnoACoMtimgWB2AD9i3cLowik5GGPtu7QGd3GFJaPnSLbV8vFxt/OBrF5fpBptCDvvN0aV9HYMlVRNiJrSJyc7kzEllNmCQR7GoyFzjnWJ2cMNp86CME/FRqNgaEAwV84x6i7W0xE=\" ],\n" +
            "    \"x5u\" : \"https://keystore.abc.org.lk/RjM3REY1MEVFMUQ2TZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ.pem\",\n" +
            "    \"x5t#S256\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\"\n" +
            "  }, {\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"kid\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"p5KzjtKkBSJRtWAmS5uekysz9Ax93ziIq-mz_0Z65Lc6EtyE9O2PO5ED5fWt8_-g1hFttbORNAH9dJF0fbwdeJclG3rKuJDzLF80rIV88cFY1Iug_kRerjlSD5yQ5bJfNeP-V7XKILo570RR7GThgLwmWNWAWKA-63zmjr1OAI2IDx5R6krlY6dPQ57euwhMS8TWpuo27CHUirKAoBzPywcssPcpfRaT0dNv_83AkxRtsOUMizAWVh8MGhUUe2bHpQdRxKD_0X7U_5V3Y0aPFUikICTW2_Je8jbQ\",\n" +
            "    \"use\" : \"sig\",\n" +
            "    \"x5c\" : [ "
            + "\"MIIDmzCCAoOgAwIBAgIJAJuzH6NrV5s5MA0GCSqGSIb3DQEBCwUAMGQxCzAJBgNVBAYTAlNMMQswCQYDVQQIDAJXUDEQMA4GA1UEBwwHQ29sb21ibzENMAsGA1UECgwE\n" +
            "d3NvMjENMAsGA1UECwwEd3NvMjEYMBYGA1UEAwwPdHJhdmVsb2NpdHkuY29tMB4X\n" +
            "DTE4MDIwNjEwNTk1N1oXDTE5MDIwNjEwNTk1N1owZDELMAkGA1UEBhMCU0wxCzAJ\n" +
            "BgNVBAgMAldQMRAwDgYDVQQHDAdDb2xvbWJvMQ0wCwYDVQQKDAR3c28yMQ0wCwYD\n" +
            "VQQLDAR3c28yMRgwFgYDVQQDDA90cmF2ZWxvY2l0eS5jb20wggEiMA0GCSqGSIb3\n" +
            "DQEBAQUAA4IBDwAwggEKAoIBAQDlKn3dmaLW7iBOKdlWY8Go8Q7kR6HNY/8j0arv\n" +
            "EcZYqMrihcSX5i5Mz57t6Z3xpaGay2jPWND7dDA/RocircleBKQk0X2OxoEYba3W\n" +
            "t477EpN9RWGAZuuANUSVKjC8FsNYhEp9y59IuxK+IgDAEfR8O2RNLYA6O3UjBC/R\n" +
            "f443CwOE4jFm3eVAeLIBudn/viC56rPBozVX4DxPaHIzxocfK6EpDljEG4lJ7otS\n" +
            "SbIpPlmAO/0f8F1Q6syv+sCkPRGn/OjTXWtUg6QXAclguOCl3MI+pLMThQUATcKb\n" +
            "2QkPl8r8/b/S8qMRKzSVYyjNP+CsDRO/MdlC50QZSJBaNYqdAgMBAAGjUDBOMB0G\n" +
            "A1UdDgQWBBSIXyhWV6Ac+FiqdXEeQwqzJfFLhDAfBgNVHSMEGDAWgBSIXyhWV6Ac\n" +
            "+FiqdXEeQwqzJfFLhDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBQ\n" +
            "S2jmfzF8x1iwmRqXILZ6qkF5ABAlNa3Z3bMFB7uErw2BxASMOLWfjZdEcyICDGIf\n" +
            "ZeYchqEPTvv/RIqDlu8xda3N2kRp1un5Hfffavm6ZWR3J8LdsnSjrehZ/afxuy8a\n" +
            "OFKiRtj9tqpG3C/s/NBJ9Gl4u5YhihOSJG9ELihJSxWDYI641AOalWnUQ/SxfeCO\n" +
            "TY75aViCAD6QDmBxe/opQYExBdgNOCQ6HdP5WWBT6EEggBe/mqOM/dchj57rpPtw\n" +
            "IOQjy9UCaY7tq4SmhAJyab0mxjcFoRBpzOJIDh+N8ozSDK+MepyFSwtW5zVacOiG\n" +
            "OQUrBTGXQFZOGKje8sbS\" ],\n" +
            "    \"x5u\" : \"https://keystore.abc.org.lk/dn/viC56rPBozVX4DxPaHIzxocfK.pem\",\n" +
            "    \"x5t#S256\" : \"JfFLhDAfBgNVHSM\"\n" +
            "  } ]\n" +
            "}";

    private static String TEST_JSON = "{\n" +
            "  \"keys\" : [ {\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"kid\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"x_AfraZx04boy3Xti7oPXMEi16ZiXWIiFy6ciFHjFZBDLEpUHJV5UaGIVl60iEHUAupKqq4hnjE4APFj1pLrs55QGDoTgSuTRw2xIzMSVjcUREM-UZFBlOXduL2B1SiYQdT8ctprJRZPvOkYZyUoYLPg9n1pEp_CVYeYhV71gLUmCmrUe52LP-TERvjk7gF16c8UCVT7G4xtzWw1hJtc1eDB5v6NsxpWRr5j2F6VdRvN__wuRRglmN1Gdw039ZvEGdCt-SEnVn4dpVuQ\",\n" +
            "    \"use\" : \"tls\",\n" +
            "    \"x5u\" : \"https://keystore.abc.org.lk/RjM3REY1MEVFMUQ2TZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ.pem\",\n" +
            "    \"x5t#S256\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\"\n" +
            "  }, {\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"kid\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"PO5ED5fWt8_-g1hFttbORNAH9dJF0fbwdeJclG3rKuJDzLF80rIV88cFY1Iug_kRerjlSD5yQ5bJfNeP-V7XKILo570RR7GThgLwmWNWAWK6dPQ57euwhMS8TWpuo27CHUirKAoBzPywcssPcpfRaT0dNv_83AkxRtsOUMizAWVh8MGhUUe2bHpQdRxKD_0X7U_5V3Y0aPFUikICTW2_Je8jbQ\",\n" +
            "    \"use\" : \"sig\",\n" +
            "    \"x5u\" : \"https://keystore.abc.org.lk/RjM3REY1MEVFMUQ2TZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ.pem\",\n" +
            "    \"x5t#S256\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\"\n" +
            "  } ]\n" +
            "}";

    private static String TEST_JSON_X5T_XCT = "{\n" + "  \"keys\" : [ {\n" + "    \"e\" : \"AQAB\",\n"
            + "    \"kid\" : \"uzPTFFKqK6VwzzdbFxmnTlE4ezc\",\n" + "    \"kty\" : \"RSA\",\n"
            + "    \"n\" : \"x_AfraZx04boy3Xti7oPXMEi16ZiXWIiFy6ci_vpQKEqGXtbKK82i68ZaHDD6EvErR8DCc6QawK5AGd_gJKFwSqB0XbB8mq15S7Sv5WnZyQFHjFZBDLEpUHJV5UaGIVl60iEHUAupKqq4hnjE4APFj1pLrs55QGDoTgSuTRw2xIzMSVjcUREM-UZFBlOXduL2B1SiYQdT8ctprJRZPvOkYZyUoYLPg9n1pEp_CVYeYhV71gLUmCmrUe52LP-TERvjk7gF16c8UCVT7G4xtzWw1hJtc1eDB5v6NsxpWRr5j2F6VdRvN__wuRRglmN1Gdw039ZvEGdCt-SEnVn4dpVuQ\",\n"
            + "    \"use\" : \"tls\",\n"
            + "    \"x5c\" : [ \"MIIFODCCBCCgAwIBAgIEWcVdrDANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJHQjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxLjAsBgNVBAMTJU9wZW5CYW5raW5nIFByZS1Qcm9kdWN0aW9uIElzc3VpbmcgQ0EwHhcNMTgxMjA1MDMwMjU4WhcNMjAwMTA1MDMzMjU4WjBhMQswCQYDVQQGEwJHQjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxGzAZBgNVBAsTEjAwMTU4MDAwMDFIUVFyWkFBWDEfMB0GA1UEAxMWMlgwMXRUTEQwaEJtd2pFZ1dWakd2ajCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMfwH62mcdOG6Mt17Yu6D1zBItemYl1iIhcunIv76UChKhl7WyivNouvGWhww+hLxK0fAwnOkGsCuQBnf4CShcEqgdF2wfJqteUu0r+Vp2ckBR4xWQQyxKVByVeVGhiFZetIhB1ALqSqquIZ4xOADxY9aS67OeUBg6E4Erk0cNsSMzElY3FERDPlGRQZTl3bi9gdUomEHU/HLaayUWT7zpGGclKGCz4PZ9aRKfwlWHmIVe9YC1Jgpq1Hudiz/kxEb45O4BdenPFAlU+xuMbc1sNYSbXNXgweb+jbMaVka+Y9helXUbzf/8LkUYJZjdRncNN/WbxBnQrfkhJ1Z+HaVbkCAwEAAaOCAgQwggIAMA4GA1UdDwEB/wQEAwIHgDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwgeAGA1UdIASB2DCB1TCB0gYLKwYBBAGodYEGAWQwgcIwKgYIKwYBBQUHAgEWHmh0dHA6Ly9vYi50cnVzdGlzLmNvbS9wb2xpY2llczCBkwYIKwYBBQUHAgIwgYYMgYNVc2Ugb2YgdGhpcyBDZXJ0aWZpY2F0ZSBjb25zdGl0dXRlcyBhY2NlcHRhbmNlIG9mIHRoZSBPcGVuQmFua2luZyBSb290IENBIENlcnRpZmljYXRpb24gUG9saWNpZXMgYW5kIENlcnRpZmljYXRlIFByYWN0aWNlIFN0YXRlbWVudDBtBggrBgEFBQcBAQRhMF8wJgYIKwYBBQUHMAGGGmh0dHA6Ly9vYi50cnVzdGlzLmNvbS9vY3NwMDUGCCsGAQUFBzAChilodHRwOi8vb2IudHJ1c3Rpcy5jb20vb2JfcHBfaXNzdWluZ2NhLmNydDA6BgNVHR8EMzAxMC+gLaArhilodHRwOi8vb2IudHJ1c3Rpcy5jb20vb2JfcHBfaXNzdWluZ2NhLmNybDAfBgNVHSMEGDAWgBRQc5HGIXLTd/T+ABIGgVx5eW4/UDAdBgNVHQ4EFgQUwA+9otHiTEen8wHnnuitXR3ZuFowDQYJKoZIhvcNAQELBQADggEBADvRik60g4F43y8YMof/Ukle3pMuRUQlIe+Nk5LXbwcOI5iMZ0h768LbmqZRqN/yRUcvAeZFXE92O59iDWbVm2zTKvGaQaUwowvi9JuH2CTLQfW5+shmvEyJnRqf2mCpJWyh4W0JgckZwtljSYR0AsNnbjNhTE86MyaRZ1Uuun2fbNfQskKHb3bkPJcRkMfplGN5Y/uNFwnanfGnoACoMtimgWB2AD9i3cLowik5GGPtu7QGd3GFJaPnSLbV8vFxt/OBrF5fpBptCDvvN0aV9HYMlVRNiJrSJyc7kzEllNmCQR7GoyFzjnWJ2cMNp86CME/FRqNgaEAwV84x6i7W0xE=\" ],\n"
            + "    \"x5t\" : \"vmeZ6lJD1EglN82nXk8qSODYxLI=\",\n"
            + "    \"x5u\" : \"https://keystore.abc.org.lk/0015800001HQQrZAAX/uzPTFFKqK6VwzzdbFxmnTlE4ezc.pem\",\n"
            + "    \"x5t#S256\" : \"tpqKoTkfPzQPxE0G-8t-sa-heMha9zGtEg0srbSTDUc=\"\n" + "  }, {\n"
            + "    \"e\" : \"AQAB\",\n" + "    \"kid\" : \"CzUe1ecMKykHLhQAATzFBudOj0Y\",\n"
            + "    \"kty\" : \"RSA\",\n"
            + "    \"n\" : \"p5KzjtKkBSJRtWAmS5ueHRQ-CCAIVvFZBIPUPCLf_N0RSo95M8gSKRVAuR0trmzoJ_L-wQkysz9Ax93ziIq-mz_0Z65Lc6EtyE9O2PO5ED5fWt8_-g1hFttbORNAH9dJF0fbwdeJclG3rKuJDzLF80rIV88cFY1Iug_kRerjlSD5yQ5bJfNeP-V7XKILo570RR7GThgLwmWNWAWKA-63zmjr1OAI2IDx5R6krlY6dPQ57euwhMS8TWpuo27CHUirKAoBzPywcssPcpfRaT0dNv_83AkxRtsOUMizAWVh8MGhUUe2bHpQdRxKD_0X7U_5V3Y0aPFUikICTW2_Je8jbQ\",\n"
            + "    \"use\" : \"sig\",\n"
            + "    \"x5c\" : [ \"MIIFLTCCBBWgAwIBAgIEWcVdrTANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJHQjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxLjAsBgNVBAMTJU9wZW5CYW5raW5nIFByZS1Qcm9kdWN0aW9uIElzc3VpbmcgQ0EwHhcNMTgxMjA1MDMwMzUyWhcNMjAwMTA1MDMzMzUyWjBhMQswCQYDVQQGEwJHQjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxGzAZBgNVBAsTEjAwMTU4MDAwMDFIUVFyWkFBWDEfMB0GA1UEAxMWMlgwMXRUTEQwaEJtd2pFZ1dWakd2ajCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKeSs47SpAUiUbVgJkubnh0UPgggCFbxWQSD1Dwi3/zdEUqPeTPIEikVQLkdLa5s6Cfy/sEJMrM/QMfd84iKvps/9GeuS3OhLchPTtjzuRA+X1rfP/oNYRbbWzkTQB/XSRdH28HXiXJRt6yriQ8yxfNKyFfPHBWNSLoP5EXq45Ug+ckOWyXzXj/le1yiC6Oe9EUexk4YC8JljVgFigPut85o69TgCNiA8eUepK5WOnT0Oe3rsITEvE1qbqNuwh1IqygKAcz8sHLLD3KX0Wk9HTb//NwJMUbbDlDIswFlYfDBoVFHtmx6UHUcSg/9F+1P+Vd2NGjxVIpCAk1tvyXvI20CAwEAAaOCAfkwggH1MA4GA1UdDwEB/wQEAwIGwDAVBgNVHSUEDjAMBgorBgEEAYI3CgMMMIHgBgNVHSAEgdgwgdUwgdIGCysGAQQBqHWBBgFkMIHCMCoGCCsGAQUFBwIBFh5odHRwOi8vb2IudHJ1c3Rpcy5jb20vcG9saWNpZXMwgZMGCCsGAQUFBwICMIGGDIGDVXNlIG9mIHRoaXMgQ2VydGlmaWNhdGUgY29uc3RpdHV0ZXMgYWNjZXB0YW5jZSBvZiB0aGUgT3BlbkJhbmtpbmcgUm9vdCBDQSBDZXJ0aWZpY2F0aW9uIFBvbGljaWVzIGFuZCBDZXJ0aWZpY2F0ZSBQcmFjdGljZSBTdGF0ZW1lbnQwbQYIKwYBBQUHAQEEYTBfMCYGCCsGAQUFBzABhhpodHRwOi8vb2IudHJ1c3Rpcy5jb20vb2NzcDA1BggrBgEFBQcwAoYpaHR0cDovL29iLnRydXN0aXMuY29tL29iX3BwX2lzc3VpbmdjYS5jcnQwOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL29iLnRydXN0aXMuY29tL29iX3BwX2lzc3VpbmdjYS5jcmwwHwYDVR0jBBgwFoAUUHORxiFy03f0/gASBoFceXluP1AwHQYDVR0OBBYEFHDTJlbYQ4XGq7ipGI9RAqjcBsw4MA0GCSqGSIb3DQEBCwUAA4IBAQB7+bZmt8tLbvFQ6Pl1Lx0R4pJCf3jHAtphrO+aoHeBkFD/R1f9kGmDZOvoI+CNStf4IR15p6mLQFS0pAJ2YuQb7fI0L/Mue7EFXb0oeQ/x0KWqv2b1WB+H0YexVzymgdCmxq7oVUY2ACCimtF0c2jULdx7J6Gsb0bnTaKIWJhYi3451vn0YtYOTPp2nzmie9GHR7ujUaXClBEEWoyhNdFJJ4rom4BhWXwanvU+leHX+sL1PBmuiEs7du/KbdUjQ6b2BXlSntSE7JNexjODdxbgSid72dv4ae+6dcwjE429kvULdMfuI7WtsvyCO2zwGqEV/0SsuXaOpioSKNNfRLw+\" ],\n"
            + "    \"x5t\" : \"qI56my8dy8V8M_ExGs2nMlD9G48=\",\n"
            + "    \"x5u\" : \"https://keystore.abc.org.lk/0015800001HQQrZAAX/CzUe1ecMKykHLhQAATzFBudOj0Y.pem\",\n"
            + "    \"x5t#S256\" : \"fMSq7nleARP8LlJGKDmYII1EjhGwBpW8BZapcCZNKSo=\"\n" + "  } ]\n" + "}";

    @DataProvider(name = "testAuthenticateClientWhenJWKSEndPointGiven")
    public Object[][] testAuthenticateClientWhenJWKSEndPointGiven() {

        Map<String, List> bodyParamsWithClientId = new HashMap<>();
        List<String> clientIdList = new ArrayList<>();
        clientIdList.add(CLIENT_ID);
        bodyParamsWithClientId.put(OAuth.OAUTH_CLIENT_ID, clientIdList);

        return new Object[][] {

                {
                        getCertificate(CERTIFICATE_CONTENT), new HashMap<String, List>(),
                        buildOAuthClientAuthnContext(CLIENT_ID), true, TEST_JSON_WITH_X5C
                },

                {
                        getCertificate(CERTIFICATE_CONTENT), bodyParamsWithClientId,
                        buildOAuthClientAuthnContext(CLIENT_ID), true, TEST_JSON_WITH_X5T
                },

                {
                        getCertificate(CERTIFICATE_CONTENT), bodyParamsWithClientId,
                        buildOAuthClientAuthnContext(CLIENT_ID), false, TEST_JSON
                },
                {
                        getCertificate(CERTIFICATE_CONTENT), bodyParamsWithClientId,
                        buildOAuthClientAuthnContext(CLIENT_ID), true, TEST_JSON_X5T_XCT
                },
                };

    }

    @DataProvider(name = "testClientAuthnData")
    public Object[][] testClientAuthnData() {

        Map<String, List> bodyParamsWithClientId = new HashMap<>();
        List<String> clientIdList = new ArrayList<>();
        clientIdList.add(CLIENT_ID);
        bodyParamsWithClientId.put(OAuth.OAUTH_CLIENT_ID, clientIdList);
        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        String subjectDN = "CN=travelocity.com, OU=wso2, O=wso2, L=Colombo, ST=WP, C=SL";
        String incorrectSubjectDN = "CN=app.com, OU=wso2, O=wso2, L=Colombo, ST=WP, C=SL";

        return new Object[][]{

                // Correct  client certificate present with client Id in request body.
                {getCertificate(CERTIFICATE_CONTENT), new HashMap<String, List>(), buildOAuthClientAuthnContext(CLIENT_ID), true, subjectDN },

                // Correct  client certificate present with client Id in request body.
                {getCertificate(CERTIFICATE_CONTENT), bodyParamsWithClientId, buildOAuthClientAuthnContext(CLIENT_ID), true, subjectDN},

                // Incorrect  client certificate present without client Id in request body.
                {getCertificate("CERTIFICATE_CONTENT"), bodyParamsWithClientId, oAuthClientAuthnContext, false, subjectDN},

                // Correct client certificate not provided.
                {null, new HashMap<String, List>(), buildOAuthClientAuthnContext(null), false, subjectDN},

                //Different subjectDN registered in application
                {getCertificate(CERTIFICATE_CONTENT), bodyParamsWithClientId, buildOAuthClientAuthnContext(CLIENT_ID), false, incorrectSubjectDN},

        };
    }

    @Test(dataProvider = "testClientAuthnData")
    public void testAuthenticateClient(Object certificate, HashMap<String, List> bodyContent,
                                       Object oAuthClientAuthnContextObj, boolean authenticationResult,
                                       String subjectDN) throws Exception {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setTlsClientAuthSubjectDN(subjectDN);
        PowerMockito.mockStatic(OAuth2Util.class);
        PowerMockito.mockStatic(MutualTLSUtil.class);
        doReturn(appDO).when(OAuth2Util.class, "getAppInformationByClientId", anyString(), anyString());
        OAuthClientAuthnContext oAuthClientAuthnContext = (OAuthClientAuthnContext) oAuthClientAuthnContextObj;
        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        PowerMockito.when(MutualTLSUtil.isJwksUriConfigured(any())).thenReturn(false);
        PowerMockito.when(OAuth2Util.getTenantDomainOfOauthApp(anyString())).thenReturn("carbon.super");
        PowerMockito.when(OAuth2Util.getX509CertOfOAuthApp(oAuthClientAuthnContext.getClientId(), "carbon.super")).thenReturn
                (getCertificate(CERTIFICATE_CONTENT));
        PowerMockito.when(httpServletRequest.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE)).thenReturn
                (certificate);
        assertEquals(mutualTLSClientAuthenticator.authenticateClient(httpServletRequest, bodyContent,
                oAuthClientAuthnContext), authenticationResult, "Expected client authentication result was not " +
                "received");
    }

    @DataProvider(name = "testCanAuthenticateData")
    public Object[][] testCanAuthenticateData() {

        return new Object[][]{

                {getCertificate(CERTIFICATE_CONTENT), new HashMap<String, List>(), false},
                {getCertificate(CERTIFICATE_CONTENT), getBodyContentWithClientId(CLIENT_ID), true},
        };
    }

    @Test(dataProvider = "testCanAuthenticateData")
    public void testCanAuthenticate(X509Certificate certificate, HashMap<String, List> bodyContent, boolean canHandle)
            throws
            Exception {

        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        PowerMockito.when(httpServletRequest.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE)).thenReturn(certificate);
        assertEquals(mutualTLSClientAuthenticator.canAuthenticate(httpServletRequest, bodyContent, new
                OAuthClientAuthnContext()), canHandle, "Expected can authenticate evaluation not received");
    }

    @Test(dataProvider = "testCanAuthenticateData")
    public void testCanAuthenticateWithHeader (X509Certificate certificate,
                                               HashMap<String, List> bodyContent, boolean canHandle) {

        mockStatic(IdentityUtil.class);
        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        when(IdentityUtil.getProperty(CommonConstants.MTLS_AUTH_HEADER)).thenReturn("x-wso2-mtls-cert");
        PowerMockito.when(httpServletRequest.getHeader("x-wso2-mtls-cert")).thenReturn(CERTIFICATE_CONTENT3);
        assertEquals(mutualTLSClientAuthenticator.canAuthenticate(httpServletRequest, bodyContent, new
                OAuthClientAuthnContext()), canHandle, "Expected can authenticate evaluation not received");
    }

    @Test
    public void testGetName() throws Exception {

        assertEquals("MutualTLSClientAuthenticator", mutualTLSClientAuthenticator.getName(), "Mutual " +
                "TLS client authenticator name has changed.");
    }

    @DataProvider(name = "testGetClientIdData")
    public Object[][] testGetClientIdData() {

        return new Object[][]{

                // Not client Id found in request body.
                {new HashMap<String, List>(), null},

                // Valid client Id in request body.
                {getBodyContentWithClientId(CLIENT_ID), CLIENT_ID},
        };
    }

    @Test(dataProvider = "testGetClientIdData")
    public void testGetClientId(HashMap<String, List> bodyContent, String clientId) throws Exception {

        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        assertEquals(mutualTLSClientAuthenticator.getClientId(httpServletRequest, bodyContent, new
                OAuthClientAuthnContext()), clientId);
    }

    private OAuthClientAuthnContext buildOAuthClientAuthnContext(String clientId) {

        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setClientId(clientId);
        return oAuthClientAuthnContext;
    }

    private X509Certificate getCertificate(String certificateContent) {

        if (StringUtils.isNotBlank(certificateContent)) {
            // Build the Certificate object from cert content.
            try {
                return (X509Certificate) IdentityUtil.convertPEMEncodedContentToCertificate(certificateContent);
            } catch (CertificateException e) {
                //do nothing
            }
        }
        return null;
    }

    public static Map<String, List<String>> getBodyContentWithClientId(String clientId) {

        Map<String, String> content = new HashMap<>();
        if (StringUtils.isNotEmpty(clientId)) {
            content.put(OAuth.OAUTH_CLIENT_ID, clientId);
        }

        Map<String, List<String>> bodyContent = new HashMap<>();
        content.forEach((key, value) -> {
            List<String> valueList = new ArrayList<String>();
            valueList.add(value);
            bodyContent.put(key, valueList);
        });
        return bodyContent;
    }

    @Test(dataProvider = "testAuthenticateClientWhenJWKSEndPointGiven")
    public void testAuthenticateClientWhenJWKSEndPointGiven(Object certificate, HashMap<String, List> bodyContent,
            Object oAuthClientAuthnContextObj, boolean authenticationResult, String testJson) throws Exception {

        PowerMockito.mockStatic(OAuth2Util.class);
        PowerMockito.mockStatic(MutualTLSUtil.class);
        MutualTLSClientAuthenticator mutualTLSClientAuthenticator1 = Mockito.spy(mutualTLSClientAuthenticator);
        OAuthClientAuthnContext oAuthClientAuthnContext = (OAuthClientAuthnContext) oAuthClientAuthnContextObj;
        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        PowerMockito.when(MutualTLSUtil.isJwksUriConfigured(any())).thenReturn(true);
        PowerMockito.when(OAuth2Util.getTenantDomainOfOauthApp(anyString()))
                .thenReturn(SUPER_TENANT_DOMAIN_NAME);
        PowerMockito
                .when(OAuth2Util.getX509CertOfOAuthApp(oAuthClientAuthnContext.getClientId(), SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(null);
        PowerMockito.doReturn(getJsonArray(testJson)).when(mutualTLSClientAuthenticator1).getResourceContent(any());
        PowerMockito.doReturn(new URL("https://wso2is.com/.well-known/jwks.json"))
                .when(mutualTLSClientAuthenticator1).getJWKSEndpointOfSP(any(),any());
        PowerMockito.when(MutualTLSUtil.getThumbPrint(any(), any())).thenReturn(
                "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        PowerMockito.when(httpServletRequest.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE)).thenReturn(certificate);
        OAuthAppDO appDO = new OAuthAppDO();
        doReturn(appDO).when(OAuth2Util.class, "getAppInformationByClientId", anyString(), anyString());
        assertEquals(mutualTLSClientAuthenticator1
                        .authenticateClient(httpServletRequest, bodyContent, oAuthClientAuthnContext), authenticationResult,
                "Expected client authentication with JWKS expected result was not received");
    }

    public static JsonArray getJsonArray(String resource) {

        JsonParser jp = new JsonParser();
        InputStream inputStream = new ByteArrayInputStream(resource.getBytes(Charset.forName("UTF-8")));
        JsonElement root = jp.parse(new InputStreamReader(inputStream));
        JsonObject rootobj = root.getAsJsonObject();
        return rootobj.get("keys").getAsJsonArray();
    }

    @Test
    public void testGetJWKSEndpointOfSP() throws Exception{
        ServiceProvider serviceProvider = new ServiceProvider();
        PowerMockito.mockStatic(MutualTLSUtil.class);
        PowerMockito.when(MutualTLSUtil.getPropertyValue(any(),any())).thenReturn("https://wso2is.com/"
                + ".well-known/jwks.json");
        assertNotNull(mutualTLSClientAuthenticator.getJWKSEndpointOfSP(serviceProvider,"someClientID"));

    }

    @Test
    public void testAuthenticate() throws Exception{
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate Cert = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(CERTIFICATE_CONTENT)));
        OAuthAppDO appDO = new OAuthAppDO();
        assertTrue(mutualTLSClientAuthenticator.authenticate(Cert,Cert, appDO));

    }

    @Test
    public void testAuthenticateWhenDifferentCertificates() throws Exception{
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate Cert = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(CERTIFICATE_CONTENT)));
        X509Certificate anotherCert = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(CERTIFICATE_CONTENT_2)));
        OAuthAppDO appDO = new OAuthAppDO();
        assertFalse(mutualTLSClientAuthenticator.authenticate(Cert,anotherCert, appDO));

    }

    @Test
    public void testCanAuthenticateWhenPKJWTAuthMethod () {

        HashMap<String, List> bodyContent = new HashMap<>();
        bodyContent.put(OAuth.OAUTH_ASSERTION_TYPE, Arrays.asList(CommonConstants.OAUTH_JWT_BEARER_GRANT_TYPE));
        bodyContent.put(OAuth.OAUTH_ASSERTION, Arrays.asList("Test_Assertion"));
        bodyContent.put(OAuth.OAUTH_CLIENT_ID, Arrays.asList(CLIENT_ID));
        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.addParameter(CommonConstants.AUTHENTICATOR_TYPE_PARAM,
                CommonConstants.AUTHENTICATOR_TYPE_PK_JWT);
        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        assertFalse(mutualTLSClientAuthenticator.canAuthenticate(httpServletRequest, bodyContent,
                oAuthClientAuthnContext));
    }

    @Test
    public void testGetSupportedClientAuthenticationMethods() {
;
        List<String> supportedAuthMethods = new ArrayList<>();
        for (ClientAuthenticationMethodModel clientAuthenticationMethodModel : mutualTLSClientAuthenticator
                .getSupportedClientAuthenticationMethods()) {
            supportedAuthMethods.add(clientAuthenticationMethodModel.getName());
        }
        Assert.assertTrue(supportedAuthMethods.contains("tls_client_auth"));
        assertEquals(supportedAuthMethods.size(), 1);
    }
}

