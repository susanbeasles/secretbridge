/*
 * Decompiled with CFR 0.152.
 */
package me.vespoli.secretbridge;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.options.Configurable;
import com.intellij.openapi.options.ConfigurationException;
import java.awt.GridLayout;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import me.vespoli.secretbridge.BridgeSettings;
import me.vespoli.secretbridge.Engine;

public final class BridgeSettingsConfigurable
implements Configurable {
    private final JTextField python = new JTextField();
    private final JTextField op = new JTextField();
    private final JTextField gh = new JTextField();
    private final JTextField aws = new JTextField();

    @Override
    public String getDisplayName() {
        return "SecretBridge";
    }

    @Override
    public JComponent createComponent() {
        JPanel panel = new JPanel(new GridLayout(0, 2, 8, 8));
        panel.add(new JLabel("Python 3.10+ executable"));
        panel.add(this.python);
        panel.add(new JLabel("1Password CLI executable"));
        panel.add(this.op);
        panel.add(new JLabel("GitHub CLI executable"));
        panel.add(this.gh);
        panel.add(new JLabel("AWS CLI v2 executable"));
        panel.add(this.aws);
        JButton prepare = new JButton("Prepare Python runtime");
        JLabel status = new JLabel("Installs the pinned GitHub encryption and AWS SDK dependencies in an isolated environment.");
        prepare.addActionListener(event -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(1);
            chooser.setDialogTitle("Choose parent folder for the SecretBridge Python runtime");
            if (chooser.showSaveDialog(panel) != 0) {
                return;
            }
            Path directory = chooser.getSelectedFile().toPath().resolve("secretbridge-runtime");
            String basePython = this.python.getText();
            prepare.setEnabled(false);
            status.setText("Preparing runtime\u2026");
            ApplicationManager.getApplication().executeOnPooledThread(() -> {
                String error = null;
                String executable = directory.resolve("bin/python3").toString();
                try {
                    if (Files.exists(directory, new LinkOption[0]) && !Files.exists(directory.resolve("pyvenv.cfg"), new LinkOption[0])) {
                        throw new IOException("Target directory already exists and is not a virtual environment");
                    }
                    if (!Files.exists(directory.resolve("pyvenv.cfg"), new LinkOption[0])) {
                        BridgeSettingsConfigurable.run(new ProcessBuilder(basePython, "-I", "-m", "venv", directory.toString()));
                    }
                    Path requirements = Files.createTempFile("secretbridge-requirements-", ".txt", new FileAttribute[0]);
                    try (InputStream input = this.getClass().getResourceAsStream("/requirements.txt");){
                        if (input == null) {
                            throw new IOException("Bundled requirements missing");
                        }
                        Files.copy(input, requirements, StandardCopyOption.REPLACE_EXISTING);
                        BridgeSettingsConfigurable.run(new ProcessBuilder(executable, "-I", "-m", "pip", "--disable-pip-version-check", "--no-input", "install", "--require-virtualenv", "-r", requirements.toString()));
                    }
                    finally {
                        Files.deleteIfExists(requirements);
                    }
                }
                catch (Exception e) {
                    error = "Runtime setup failed. Check the Python executable, directory permissions, and package-network access.";
                }
                String result = error;
                ApplicationManager.getApplication().invokeLater(() -> {
                    prepare.setEnabled(true);
                    if (result == null) {
                        this.python.setText(executable);
                        status.setText("Ready. Click Apply to use this Python runtime.");
                    } else {
                        status.setText(result);
                    }
                });
            });
        });
        panel.add(prepare);
        panel.add(status);
        panel.add(new JLabel("Authentication uses vendor CLIs; no credentials are stored here."));
        panel.add(new JLabel());
        this.reset();
        return panel;
    }

    private static void run(ProcessBuilder builder) throws Exception {
        builder.redirectErrorStream(true);
        Process process = builder.start();
        CompletableFuture<byte[]> output = CompletableFuture.supplyAsync(() -> Engine.read(process.getInputStream()));
        try {
            if (!process.waitFor(300L, TimeUnit.SECONDS) || process.exitValue() != 0) {
                throw new IOException("Runtime setup failed");
            }
            output.get();
        }
        finally {
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    @Override
    public boolean isModified() {
        BridgeSettings.Data s = BridgeSettings.get().getState();
        return !this.python.getText().equals(s.python) || !this.op.getText().equals(s.op) || !this.gh.getText().equals(s.gh) || !this.aws.getText().equals(s.aws);
    }

    @Override
    public void apply() throws ConfigurationException {
        for (JTextField field : new JTextField[]{this.python, this.op, this.gh, this.aws}) {
            if (Path.of(field.getText(), new String[0]).isAbsolute()) continue;
            throw new ConfigurationException("Executable paths must be absolute.");
        }
        BridgeSettings.Data s = BridgeSettings.get().getState();
        s.python = this.python.getText();
        s.op = this.op.getText();
        s.gh = this.gh.getText();
        s.aws = this.aws.getText();
    }

    @Override
    public void reset() {
        BridgeSettings.Data s = BridgeSettings.get().getState();
        this.python.setText(s.python);
        this.op.setText(s.op);
        this.gh.setText(s.gh);
        this.aws.setText(s.aws);
    }
}
