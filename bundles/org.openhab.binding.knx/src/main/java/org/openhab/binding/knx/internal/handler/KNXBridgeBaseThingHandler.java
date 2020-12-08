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
package org.openhab.binding.knx.internal.handler;

import java.io.File;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.knx.internal.client.KNXClient;
import org.openhab.binding.knx.internal.client.StatusUpdateCallback;
import org.openhab.core.OpenHAB;
import org.openhab.core.common.ThreadPoolManager;
import org.openhab.core.thing.Bridge;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.ThingStatusDetail;
import org.openhab.core.thing.binding.BaseBridgeHandler;
import org.openhab.core.types.Command;

import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.mgmt.Destination;
import tuwien.auto.calimero.secure.Keyring;
import tuwien.auto.calimero.secure.KnxSecureException;
import tuwien.auto.calimero.secure.Security;

/**
 * The {@link KNXBridgeBaseThingHandler} is responsible for handling commands, which are
 * sent to one of the channels.
 *
 * @author Simon Kaufmann - Initial contribution and API
 */
@NonNullByDefault
public abstract class KNXBridgeBaseThingHandler extends BaseBridgeHandler implements StatusUpdateCallback {

    protected ConcurrentHashMap<IndividualAddress, Destination> destinations = new ConcurrentHashMap<>();
    private final ScheduledExecutorService knxScheduler = ThreadPoolManager.getScheduledPool("knx");
    private final ScheduledExecutorService backgroundScheduler = Executors.newSingleThreadScheduledExecutor();
    private @Nullable Keyring keyring;
    private @Nullable String keyringPassword;

    public KNXBridgeBaseThingHandler(Bridge bridge) {
        super(bridge);
    }

    protected abstract KNXClient getClient();

    protected boolean initializeSecurity(String keyringFile, String password) {
        keyring = null;
        keyringPassword = null;

        if (keyringFile == null || keyringFile.trim().isEmpty())
            return false;
        try {
            // load keyring file from config dir, folder misc
            String keyringUri = OpenHAB.getConfigFolder() + File.separator + "misc" + File.separator
                    + keyringFile.trim();
            keyring = Keyring.load(keyringUri);
            if (keyring == null)
                throw new KnxSecureException("keyring file configured, but loading failed: " + keyringUri);

            // loading was successful, check signatures
            if (!keyring.verifySignature(password.toCharArray()))
                throw new KnxSecureException("signature verification failed, please check keyring file: " + keyringUri);
            keyringPassword = password;

            // Add to global static key(ring) storage of Calimero library.
            // More than one can be added ONLY IF addresses are different,
            // as Calimero adds all information to this static object.
            // -> to be discussed with owner of Calimero lib.
            Security.defaultInstallation().useKeyring(keyring, keyringPassword.toCharArray());
        } catch (KnxSecureException e) {
            keyring = null;
            keyringPassword = null;
            throw e;
        }
        return true;
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {
        // Nothing to do here
    }

    public ScheduledExecutorService getScheduler() {
        return knxScheduler;
    }

    public ScheduledExecutorService getBackgroundScheduler() {
        return backgroundScheduler;
    }

    @Override
    public void updateStatus(ThingStatus status) {
        super.updateStatus(status);
    }

    @Override
    public void updateStatus(ThingStatus status, ThingStatusDetail statusDetail, @Nullable String description) {
        super.updateStatus(status, statusDetail, description);
    }
}
