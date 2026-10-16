/*
 * Decompiled with CFR 0.152.
 */
package me.vespoli.secretbridge;

import com.intellij.execution.configurations.ConfigurationFactory;
import com.intellij.execution.configurations.ConfigurationType;
import com.intellij.execution.configurations.RunConfiguration;
import com.intellij.icons.AllIcons;
import com.intellij.openapi.project.Project;
import javax.swing.Icon;
import me.vespoli.secretbridge.SecretRunConfiguration;
import org.jetbrains.annotations.NotNull;

public final class SecretRunType
implements ConfigurationType {
    private final ConfigurationFactory factory = new ConfigurationFactory(this){

        @Override
        @NotNull
        public String getId() {
            return "SecretBridgeApplication";
        }

        @Override
        @NotNull
        public RunConfiguration createTemplateConfiguration(@NotNull Project project) {
            if (project == null) {
                $$$reportNull$$$0(0);
            }
            return new SecretRunConfiguration(project, this, "Application with 1Password");
        }

        private static /* synthetic */ void $$$reportNull$$$0(int n) {
            throw new IllegalArgumentException(String.format("Argument for @NotNull parameter '%s' of %s.%s must not be null", "project", "me/vespoli/secretbridge/SecretRunType$1", "createTemplateConfiguration"));
        }
    };

    @Override
    @NotNull
    public String getDisplayName() {
        return "SecretBridge Application";
    }

    @Override
    public String getConfigurationTypeDescription() {
        return "Run any application with environment secrets resolved by 1Password";
    }

    @Override
    public Icon getIcon() {
        return AllIcons.RunConfigurations.Application;
    }

    @Override
    @NotNull
    public String getId() {
        return "SecretBridgeApplicationType";
    }

    @Override
    public ConfigurationFactory @NotNull [] getConfigurationFactories() {
        ConfigurationFactory[] configurationFactoryArray = new ConfigurationFactory[]{this.factory};
        if (configurationFactoryArray == null) {
            SecretRunType.$$$reportNull$$$0(0);
        }
        return configurationFactoryArray;
    }

    private static /* synthetic */ void $$$reportNull$$$0(int n) {
        throw new IllegalStateException(String.format("@NotNull method %s.%s must not return null", "me/vespoli/secretbridge/SecretRunType", "getConfigurationFactories"));
    }
}
