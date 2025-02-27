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
package org.openhab.binding.boschshc.internal.devices.bridge.dto;

import java.util.List;

/**
 * A container object for faults that can be contained in {@link DeviceServiceData}.
 * <p>
 * Example JSON:
 *
 * <pre>
 * "faults": {
 *   "entries": [
 *     {
 *       "type":"LOW_BATTERY",
 *       "category":"WARNING"
 *     }
 *   ]
   }
 * </pre>
 *
 * @author David Pace - Initial contribution
 *
 */
public class Faults {

    public List<Fault> entries;
}
