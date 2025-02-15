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
package org.openhab.binding.lcn.internal.connection;

import org.eclipse.jdt.annotation.NonNullByDefault;

/**
 * Handles events from the connection to the LCN-PCK gateway.
 *
 * @author Tobias Jüttner - Initial Contribution
 * @author Fabian Wolter - Migration to OH2
 */
@NonNullByDefault
public interface ConnectionCallback {
    /**
     * Invoked when the Connection to the PCK gateway is established and the LCN bus is connected to the PCK gateway.
     */
    void onOnline();

    /**
     * Invoked when the Connection to the PCK gateway has been closed or when the LCN bus is disconnected from the PCK
     * gateway.
     *
     * @param errorMessage the reason
     */
    void onOffline(String errorMessage);

    /**
     * Invoked when a PCK message has been reived from the PCK gateway.
     *
     * @param message the received message
     */
    void onPckMessageReceived(String message);
}
