/*
 * Decompiled with CFR 0.152.
 */
package me.vespoli.secretbridge;

import com.google.gson.JsonObject;
import com.intellij.execution.ExecutionException;
import com.intellij.execution.Executor;
import com.intellij.execution.configurations.CommandLineState;
import com.intellij.execution.configurations.ConfigurationFactory;
import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.configurations.RunConfigurationBase;
import com.intellij.execution.configurations.RunConfigurationOptions;
import com.intellij.execution.configurations.RunProfileState;
import com.intellij.execution.configurations.RuntimeConfigurationError;
import com.intellij.execution.configurations.RuntimeConfigurationException;
import com.intellij.execution.process.KillableColoredProcessHandler;
import com.intellij.execution.process.ProcessHandler;
import com.intellij.execution.runners.ExecutionEnvironment;
import com.intellij.openapi.options.SettingsEditor;
import com.intellij.openapi.project.Project;
import com.intellij.util.execution.ParametersListUtil;
import java.awt.GridLayout;
import java.io.IOException;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import me.vespoli.secretbridge.Engine;
import org.jdom.Element;
import org.jetbrains.annotations.NotNull;

public final class SecretRunConfiguration
extends RunConfigurationBase<RunConfigurationOptions> {
    String environment = "development";
    String command = "node server.js";

    SecretRunConfiguration(Project project, ConfigurationFactory factory, String name) {
        super(project, factory, name);
    }

    @Override
    public void readExternal(@NotNull Element element) {
        if (element == null) {
            SecretRunConfiguration.$$$reportNull$$$0(0);
        }
        super.readExternal(element);
        this.environment = element.getAttributeValue("secretbridgeEnvironment", "development");
        this.command = element.getAttributeValue("secretbridgeCommand", "node server.js");
    }

    @Override
    public void writeExternal(@NotNull Element element) {
        if (element == null) {
            SecretRunConfiguration.$$$reportNull$$$0(1);
        }
        super.writeExternal(element);
        element.setAttribute("secretbridgeEnvironment", this.environment);
        element.setAttribute("secretbridgeCommand", this.command);
    }

    @NotNull
    public SettingsEditor<SecretRunConfiguration> getConfigurationEditor() {
        return new SettingsEditor<SecretRunConfiguration>(){
            final JTextField env = new JTextField();
            final JTextField cmd = new JTextField();

            @Override
            protected void resetEditorFrom(@NotNull SecretRunConfiguration config) {
                if (config == null) {
                    $$$reportNull$$$0(0);
                }
                this.env.setText(config.environment);
                this.cmd.setText(config.command);
            }

            @Override
            protected void applyEditorTo(@NotNull SecretRunConfiguration config) {
                if (config == null) {
                    $$$reportNull$$$0(1);
                }
                config.environment = this.env.getText();
                config.command = this.cmd.getText();
            }

            @Override
            @NotNull
            protected JComponent createEditor() {
                JPanel panel = new JPanel(new GridLayout(0, 2, 8, 8));
                panel.add(new JLabel("Manifest environment"));
                panel.add(this.env);
                panel.add(new JLabel("Command and arguments"));
                panel.add(this.cmd);
                panel.add(new JLabel("Use executable arguments; shell syntax is not evaluated."));
                panel.add(new JLabel());
                JPanel jPanel = panel;
                if (jPanel == null) {
                    $$$reportNull$$$0(2);
                }
                return jPanel;
            }

            private static /* synthetic */ void $$$reportNull$$$0(int n) {
                Object[] objectArray;
                Object[] objectArray2;
                Object[] objectArray3 = new Object[switch (n) {
                    default -> 3;
                    case 2 -> 2;
                }];
                switch (n) {
                    default: {
                        objectArray2 = objectArray3;
                        objectArray3[0] = "config";
                        break;
                    }
                    case 2: {
                        objectArray2 = objectArray3;
                        objectArray3[0] = "me/vespoli/secretbridge/SecretRunConfiguration$1";
                        break;
                    }
                }
                switch (n) {
                    default: {
                        objectArray = objectArray2;
                        objectArray2[1] = "me/vespoli/secretbridge/SecretRunConfiguration$1";
                        break;
                    }
                    case 2: {
                        objectArray = objectArray2;
                        objectArray2[1] = "createEditor";
                        break;
                    }
                }
                switch (n) {
                    default: {
                        objectArray = objectArray;
                        objectArray[2] = "resetEditorFrom";
                        break;
                    }
                    case 1: {
                        objectArray = objectArray;
                        objectArray[2] = "applyEditorTo";
                        break;
                    }
                    case 2: {
                        break;
                    }
                }
                String string = String.format(n == 2 ? "@NotNull method %s.%s must not return null" : "Argument for @NotNull parameter '%s' of %s.%s must not be null", objectArray);
                throw switch (n) {
                    default -> new IllegalArgumentException(string);
                    case 2 -> new IllegalStateException(string);
                };
            }
        };
    }

    @Override
    public void checkConfiguration() throws RuntimeConfigurationException {
        if (this.environment.isBlank() || this.command.isBlank()) {
            throw new RuntimeConfigurationError("Choose an environment and application command");
        }
        try {
            JsonObject envs = Engine.config(this.getProject()).getAsJsonObject("environments");
            if (!envs.has(this.environment)) {
                throw new RuntimeConfigurationError("Environment is absent from secretbridge.json");
            }
        }
        catch (RuntimeConfigurationException e) {
            throw e;
        }
        catch (Exception e) {
            throw new RuntimeConfigurationError("Configure secretbridge.json first");
        }
    }

    @Override
    public RunProfileState getState(@NotNull Executor executor, @NotNull ExecutionEnvironment executionEnvironment) {
        if (executor == null) {
            SecretRunConfiguration.$$$reportNull$$$0(2);
        }
        if (executionEnvironment == null) {
            SecretRunConfiguration.$$$reportNull$$$0(3);
        }
        return new CommandLineState(executionEnvironment){

            @Override
            @NotNull
            protected ProcessHandler startProcess() throws ExecutionException {
                try {
                    GeneralCommandLine cli = Engine.command(SecretRunConfiguration.this.getProject(), "run", SecretRunConfiguration.this.environment, "--");
                    cli.addParameters(ParametersListUtil.parse(SecretRunConfiguration.this.command));
                    return new KillableColoredProcessHandler(cli);
                }
                catch (IOException e) {
                    throw new ExecutionException("Unable to start the bundled secrets engine", e);
                }
            }
        };
    }

    private static /* synthetic */ void $$$reportNull$$$0(int n) {
        Object[] objectArray;
        Object[] objectArray2;
        Object[] objectArray3 = new Object[3];
        switch (n) {
            default: {
                objectArray2 = objectArray3;
                objectArray3[0] = "element";
                break;
            }
            case 2: {
                objectArray2 = objectArray3;
                objectArray3[0] = "executor";
                break;
            }
            case 3: {
                objectArray2 = objectArray3;
                objectArray3[0] = "executionEnvironment";
                break;
            }
        }
        objectArray2[1] = "me/vespoli/secretbridge/SecretRunConfiguration";
        switch (n) {
            default: {
                objectArray = objectArray2;
                objectArray2[2] = "readExternal";
                break;
            }
            case 1: {
                objectArray = objectArray2;
                objectArray2[2] = "writeExternal";
                break;
            }
            case 2:
            case 3: {
                objectArray = objectArray2;
                objectArray2[2] = "getState";
                break;
            }
        }
        throw new IllegalArgumentException(String.format("Argument for @NotNull parameter '%s' of %s.%s must not be null", objectArray));
    }
}
