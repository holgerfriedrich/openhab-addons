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
package org.openhab.binding.gree.internal.gson;

/**
 *
 * The GreeExecResponseDTO class is used by Gson to hold values returned from
 * the Air Conditioner during requests for Execution of Commands to the
 * Air Conditioner.
 *
 * @author John Cunha - Initial contribution
 */
public class GreeExecResponseDTO extends GreeResponseBaseDTO {
    public transient GreeExecResponsePackDTO packJson = null;
}
