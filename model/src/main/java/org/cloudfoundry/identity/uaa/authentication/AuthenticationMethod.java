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

import com.fasterxml.jackson.annotation.JsonValue;

import static org.springframework.util.StringUtils.hasText;

public enum AuthenticationMethod {

    FACE("face", "Facial recognition", ""),
    FINGERPRINT("fpt", "Fingerprint biometric", ""),
    GEOLOCATION("geo", "Use of geolocation information", ""),
    PROOF_OF_POSESSION(
        "hwk",
        "Proof-of-possession (PoP) of a hardware-secured key.",
        "See https://tools.ietf.org/html/rfc4211#appendix-C"
    ),
    IRIS("iris", "Iris scan biometric", ""),
    KNOWLEDGE(
        "kba",
        "Knowledge-based authentication",
        "See https://tools.ietf.org/html/draft-ietf-oauth-amr-values-04#ref-NIST.800-63-2\n" +
        "See https://tools.ietf.org/html/draft-ietf-oauth-amr-values-04#ref-ISO29115"
    ),
    MULTI_CHANNEL(
        "mca",
        "Multiple-channel authentication.",
        "The authentication involves\n" +
            "communication over more than one distinct communication channel.\n" +
            "For instance, a multiple-channel authentication might involve both\n" +
            "entering information into a workstation's browser and providing\n" +
            "information on a telephone call to a pre-registered number."
    ),
    MULTI_FACTOR(
        "mfa",
        "Multiple-factor authentication",
        "Multiple-factor authentication [NIST.800-63-2]," +
            "https://tools.ietf.org/html/draft-ietf-oauth-amr-values-04#ref-NIST.800-63-2\n"+
            "[ISO29115], https://tools.ietf.org/html/draft-ietf-oauth-amr-values-04#ref-ISO29115.\n"+
            "When this is present, specific authentication methods used may also be included."
    ),
    ONE_TIME_PASSCODE(
        "otp",
        "One-time password.",
        "One-time password specifications that this\n" +
            "authentication method applies to include\n"+
            "[RFC4226], https://tools.ietf.org/html/rfc4226 and\n"+
            "[RFC6238], https://tools.ietf.org/html/rfc6238"
    ),
    PIN(
        "pin",
        "Personal Identification Number",
        "Personal Identification Number or pattern (not restricted to\n" +
            "containing only numbers) that a user enters to unlock a key on the\n" +
            "device.  This mechanism should have a way to deter an attacker\n" +
            "from obtaining the PIN by trying repeated guesses.\n"
    ),
    PASSWORD("pwd", "Password-based authentication", ""),
    RISK("rba", "Risk-based authentication", "https://tools.ietf.org/html/draft-ietf-oauth-amr-values-04#ref-JECM"),
    RETINA("retina", "Retina scan biometric", "");


    private String amr;
    private String name;
    private String description;

    AuthenticationMethod(String amr, String name, String description) {
        this.amr = amr;
        this.name = name;
        this.description = description;
    }

    @JsonValue
    public String getAMR() {
        return amr;
    }

    public static AuthenticationMethod fromAMR(String amr) {
        if (!hasText(amr)) {
            return null;
        }
        switch (amr) {
            case "face" : return FACE;
            case "ftp" : return FINGERPRINT;
            case "geo" : return GEOLOCATION;
            case "hwk" : return PROOF_OF_POSESSION;
            case "iris" : return IRIS;
            case "kba" : return KNOWLEDGE;
            case "mca" : return MULTI_CHANNEL;
            case "mfa" : return MULTI_FACTOR;
            case "otp" : return ONE_TIME_PASSCODE;
            case "pin" : return PIN;
            case "pwd" : return PASSWORD;
            case "rba" : return RISK;
            case "retina" : return RETINA;
            default: throw new IllegalArgumentException(amr);
        }
    }

    @Override
    public String toString() {
        return getAMR();
    }
}
