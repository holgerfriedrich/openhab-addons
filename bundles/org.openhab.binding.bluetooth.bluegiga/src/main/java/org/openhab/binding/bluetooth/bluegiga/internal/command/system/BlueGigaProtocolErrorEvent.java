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
package org.openhab.binding.bluetooth.bluegiga.internal.command.system;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.binding.bluetooth.bluegiga.internal.BlueGigaResponse;
import org.openhab.binding.bluetooth.bluegiga.internal.enumeration.BgApiResponse;

/**
 * Class to implement the BlueGiga command <b>protocolErrorEvent</b>.
 * <p>
 * A protocol error was detected in BGAPI command parser. This event is triggered if a BGAPI
 * command from the host contains syntax error(s), or if a command is only partially sent. Then
 * the BGAPI parser has a 1 second command timeout and if a valid command is not transmitted
 * within this timeout an error is raised and the partial or wrong command will be ignored.
 * <p>
 * This class provides methods for processing BlueGiga API commands.
 * <p>
 * Note that this code is autogenerated. Manual changes may be overwritten.
 *
 * @author Chris Jackson - Initial contribution of Java code generator
 */
@NonNullByDefault
public class BlueGigaProtocolErrorEvent extends BlueGigaResponse {
    public static final int COMMAND_CLASS = 0x00;
    public static final int COMMAND_METHOD = 0x06;

    /**
     * Reason for failure
     * <p>
     * BlueGiga API type is <i>BgApiResponse</i> - Java type is {@link BgApiResponse}
     */
    private BgApiResponse reason;

    /**
     * Event constructor
     */
    public BlueGigaProtocolErrorEvent(int[] inputBuffer) {
        // Super creates deserializer and reads header fields
        super(inputBuffer);

        event = (inputBuffer[0] & 0x80) != 0;

        // Deserialize the fields
        reason = deserializeBgApiResponse();
    }

    /**
     * Reason for failure
     * <p>
     * BlueGiga API type is <i>BgApiResponse</i> - Java type is {@link BgApiResponse}
     *
     * @return the current reason as {@link BgApiResponse}
     */
    public BgApiResponse getReason() {
        return reason;
    }

    @Override
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        builder.append("BlueGigaProtocolErrorEvent [reason=");
        builder.append(reason);
        builder.append(']');
        return builder.toString();
    }
}
