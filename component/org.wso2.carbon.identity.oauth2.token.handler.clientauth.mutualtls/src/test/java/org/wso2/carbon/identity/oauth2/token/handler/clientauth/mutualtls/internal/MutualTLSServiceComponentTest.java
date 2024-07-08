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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.internal;

import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.MutualTLSClientAuthenticator;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Unit tests for MutualTLSServiceComponent class.
 */
@PrepareForTest({BundleContext.class, ComponentContext.class})
public class MutualTLSServiceComponentTest {

    @Test
    public void testActivate() throws Exception {

        BundleContext bundleContext = mock(BundleContext.class);
        ComponentContext context = mock(ComponentContext.class);
        when(context.getBundleContext()).thenReturn(bundleContext);

        final String[] serviceName = new String[1];

        doAnswer(new Answer<Object>() {

            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                MutualTLSClientAuthenticator
                        mutualTLSClientAuthenticator = (MutualTLSClientAuthenticator) invocation.getArguments()[1];
                serviceName[0] = mutualTLSClientAuthenticator.getClass().getName();
                return null;
            }
        }).when(bundleContext).registerService(anyString(), any(MutualTLSClientAuthenticator.class), any());

        MutualTLSServiceComponent mutualTLSServiceComponent = new MutualTLSServiceComponent();
        mutualTLSServiceComponent.activate(context);

        assertEquals(MutualTLSClientAuthenticator.class.getName(), serviceName[0], "error");
    }

}
