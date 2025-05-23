/*
 * Copyright (c) 2010-2025 Contributors to the openHAB project
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
package org.openhab.binding.mqtt.homie;

import static org.openhab.binding.mqtt.homie.generic.internal.MqttBindingConstants.HOMIE300_MQTT_THING;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.thing.ThingUID;

/**
 * Static test definitions, like thing, bridge and channel definitions
 *
 * @author David Graeff - Initial contribution
 */
@NonNullByDefault
public class ThingChannelConstants {
    // Common ThingUID and ChannelUIDs
    public static final ThingUID TEST_HOME_THING = new ThingUID(HOMIE300_MQTT_THING, "device123");
}
