/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.cloudfoundry.identity.uaa.authentication.AuthenticationMethod.FACE;
import static org.cloudfoundry.identity.uaa.authentication.AuthenticationMethod.FINGERPRINT;
import static org.cloudfoundry.identity.uaa.authentication.AuthenticationMethod.GEOLOCATION;
import static org.cloudfoundry.identity.uaa.authentication.AuthenticationMethod.IRIS;
import static org.cloudfoundry.identity.uaa.authentication.AuthenticationMethod.KNOWLEDGE;
import static org.cloudfoundry.identity.uaa.authentication.AuthenticationMethod.MULTI_CHANNEL;
import static org.cloudfoundry.identity.uaa.authentication.AuthenticationMethod.MULTI_FACTOR;
import static org.cloudfoundry.identity.uaa.authentication.AuthenticationMethod.ONE_TIME_PASSCODE;
import static org.cloudfoundry.identity.uaa.authentication.AuthenticationMethod.PASSWORD;
import static org.cloudfoundry.identity.uaa.authentication.AuthenticationMethod.PIN;
import static org.cloudfoundry.identity.uaa.authentication.AuthenticationMethod.PROOF_OF_POSESSION;
import static org.cloudfoundry.identity.uaa.authentication.AuthenticationMethod.RETINA;
import static org.cloudfoundry.identity.uaa.authentication.AuthenticationMethod.RISK;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.*;


public class AuthenticationMethodTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void fromAMR() throws Exception {
        assertSame(FACE, AuthenticationMethod.fromAMR("face"));
        assertSame(FINGERPRINT, AuthenticationMethod.fromAMR("ftp"));
        assertSame(GEOLOCATION, AuthenticationMethod.fromAMR("geo"));
        assertSame(PROOF_OF_POSESSION, AuthenticationMethod.fromAMR("hwk"));
        assertSame(IRIS, AuthenticationMethod.fromAMR("iris"));
        assertSame(KNOWLEDGE, AuthenticationMethod.fromAMR("kba"));
        assertSame(MULTI_CHANNEL, AuthenticationMethod.fromAMR("mca"));
        assertSame(MULTI_FACTOR, AuthenticationMethod.fromAMR("mfa"));
        assertSame(ONE_TIME_PASSCODE, AuthenticationMethod.fromAMR("otp"));
        assertSame(PIN, AuthenticationMethod.fromAMR("pin"));
        assertSame(PASSWORD, AuthenticationMethod.fromAMR("pwd"));
        assertSame(RISK, AuthenticationMethod.fromAMR("rba"));
        assertSame(RETINA, AuthenticationMethod.fromAMR("retina"));
        assertNull(AuthenticationMethod.fromAMR(""));
        assertNull(AuthenticationMethod.fromAMR(null));
    }

    @Test
    public void invalidAMR() {
        String amr = "invalid";
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage(amr);
        AuthenticationMethod.fromAMR(amr);
    }

    @Test
    public void testJSON() {
        testJSON(FACE);
        testJSON(FINGERPRINT);
        testJSON(GEOLOCATION);
        testJSON(PROOF_OF_POSESSION);
        testJSON(IRIS);
        testJSON(KNOWLEDGE);
        testJSON(MULTI_CHANNEL);
        testJSON(MULTI_FACTOR);
        testJSON(ONE_TIME_PASSCODE);
        testJSON(PIN);
        testJSON(PASSWORD);
        testJSON(RISK);
        testJSON(RETINA);
    }

    public void testJSON(AuthenticationMethod type) {
        AuthenticationTypeHolder holder = new AuthenticationTypeHolder();
        holder.setType(type);

        String json = JsonUtils.writeValueAsString(holder);
        assertThat(json, containsString(type.getAMR()));

        AuthenticationTypeHolder deserialized = JsonUtils.readValue(json, AuthenticationTypeHolder.class);

        assertSame(holder.getType(), deserialized.getType());
    }

    public static class AuthenticationTypeHolder {
        AuthenticationMethod type;

        public AuthenticationMethod getType() {
            return type;
        }

        public void setType(AuthenticationMethod type) {
            this.type = type;
        }
    }

}