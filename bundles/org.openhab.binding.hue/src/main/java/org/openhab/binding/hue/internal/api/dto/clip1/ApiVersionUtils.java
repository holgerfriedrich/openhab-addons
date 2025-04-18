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
package org.openhab.binding.hue.internal.api.dto.clip1;

import org.eclipse.jdt.annotation.NonNullByDefault;

/**
 * @author Samuel Leisering - Initial contribution
 */
@NonNullByDefault
public final class ApiVersionUtils {

    private static final ApiVersion FULL_LIGHTS = new ApiVersion(1, 11, 0);

    ApiVersionUtils() {
    }

    /**
     * Starting from version 1.11, <code>GET</code>ing the Lights always returns {@link FullLight}s instead of
     * {@link HueObject}s.
     *
     * @return
     */
    public static boolean supportsFullLights(ApiVersion version) {
        return FULL_LIGHTS.compare(version) <= 0;
    }
}
