/**
 * Copyright (c) 2010-2021 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.knx.internal.security;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;

import org.junit.jupiter.api.Test;

import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.secure.Keyring;
import tuwien.auto.calimero.secure.Security;

/**
 *
 * @author Simon Kaufmann - initial contribution and API
 *
 */
public class KNXSecurityTest {

    @Test
    public void testCalimero_keyring() {
        final String testFile = getClass().getClassLoader().getResource("test.knxkeys").toString();
        final char[] password = "habopen".toCharArray();

        assertNotEquals("", testFile);
        Keyring keys = Keyring.load(testFile);
        assertTrue(keys.verifySignature(password));

        System.out.println(keys.devices().toString());
        System.out.println(keys.groups().toString());
        System.out.println(keys.interfaces().toString());

        GroupAddress ga = new GroupAddress(8, 0, 0);
        byte[] key800enc = keys.groups().get(ga);
        assertNotEquals(0, key800enc.length);
        byte[] key800dec = keys.decryptKey(key800enc, password);
        assertEquals(16, key800dec.length);

        IndividualAddress pa = new IndividualAddress(1, 2, 72);
        Keyring.Device dev = keys.devices().get(pa);
        // cannot check this for dummy test file, needs real device to be included
        // assertNotEquals(0, dev.sequenceNumber());

        // currently Calimero uses _one_ static map to store all keys
        // -> check if this is still the case
        Security.defaultInstallation().useKeyring(keys, password);
        Map<GroupAddress, byte[]> groupKeys = Security.defaultInstallation().groupKeys();
        assertEquals(3, groupKeys.size());
        groupKeys.remove(ga);
        assertEquals(2, groupKeys.size());
        Security.defaultInstallation().useKeyring(keys, password);
        Map<GroupAddress, byte[]> groupKeys2 = Security.defaultInstallation().groupKeys();
        assertEquals(3, groupKeys2.size());
        assertEquals(3, groupKeys.size());
        ga = new GroupAddress(1, 0, 0);
        groupKeys.put(ga, new byte[1]);
        assertEquals(4, groupKeys2.size());
        assertEquals(4, groupKeys.size());
        Security.defaultInstallation().useKeyring(keys, password);
        assertEquals(4, groupKeys2.size());
        assertEquals(4, groupKeys.size());
    }
}
