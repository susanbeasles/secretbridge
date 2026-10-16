/*
 * Decompiled with CFR 0.152.
 */
package me.vespoli.secretbridge;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.PersistentStateComponent;
import com.intellij.openapi.components.Service;
import com.intellij.openapi.components.State;
import com.intellij.openapi.components.Storage;
import org.jetbrains.annotations.NotNull;

@State(name="SecretBridge", storages={@Storage(value="secretbridge.xml")})
@Service(value={Service.Level.APP})
public final class BridgeSettings
implements PersistentStateComponent<BridgeSettings.Data> {
    private Data state = new Data();

    public static BridgeSettings get() {
        return ApplicationManager.getApplication().getService(BridgeSettings.class);
    }

    @Override
    @NotNull
    public Data getState() {
        Data data = this.state;
        if (data == null) {
            BridgeSettings.$$$reportNull$$$0(0);
        }
        return data;
    }

    @Override
    public void loadState(@NotNull Data value) {
        if (value == null) {
            BridgeSettings.$$$reportNull$$$0(1);
        }
        this.state = value;
    }

    private static /* synthetic */ void $$$reportNull$$$0(int n) {
        Object[] objectArray;
        Object[] objectArray2;
        Object[] objectArray3 = new Object[switch (n) {
            default -> 2;
            case 1 -> 3;
        }];
        switch (n) {
            default: {
                objectArray2 = objectArray3;
                objectArray3[0] = "me/vespoli/secretbridge/BridgeSettings";
                break;
            }
            case 1: {
                objectArray2 = objectArray3;
                objectArray3[0] = "value";
                break;
            }
        }
        switch (n) {
            default: {
                objectArray = objectArray2;
                objectArray2[1] = "getState";
                break;
            }
            case 1: {
                objectArray = objectArray2;
                objectArray2[1] = "me/vespoli/secretbridge/BridgeSettings";
                break;
            }
        }
        switch (n) {
            default: {
                break;
            }
            case 1: {
                objectArray = objectArray;
                objectArray[2] = "loadState";
                break;
            }
        }
        String string = String.format(n == 1 ? "Argument for @NotNull parameter '%s' of %s.%s must not be null" : "@NotNull method %s.%s must not return null", objectArray);
        throw switch (n) {
            default -> new IllegalStateException(string);
            case 1 -> new IllegalArgumentException(string);
        };
    }

    public static class Data {
        public String python = "/usr/local/bin/python3";
        public String op = "/usr/local/bin/op";
        public String gh = "/usr/local/bin/gh";
        public String aws = "/usr/local/bin/aws";
    }
}
