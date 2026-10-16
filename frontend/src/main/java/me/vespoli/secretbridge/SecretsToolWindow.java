/*
 * Decompiled with CFR 0.152.
 */
package me.vespoli.secretbridge;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.fileEditor.FileEditorManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.vfs.LocalFileSystem;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.content.ContentFactory;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import me.vespoli.secretbridge.BridgeSettings;
import me.vespoli.secretbridge.Engine;
import org.jetbrains.annotations.NotNull;

public final class SecretsToolWindow
implements ToolWindowFactory {
    @Override
    public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow window) {
        if (project == null) {
            SecretsToolWindow.$$$reportNull$$$0(0);
        }
        if (window == null) {
            SecretsToolWindow.$$$reportNull$$$0(1);
        }
        Panel panel = new Panel(project);
        window.getContentManager().addContent(ContentFactory.getInstance().createContent(panel, "Application secrets", false));
    }

    private static /* synthetic */ void $$$reportNull$$$0(int n) {
        Object[] objectArray;
        Object[] objectArray2 = new Object[3];
        switch (n) {
            default: {
                objectArray = objectArray2;
                objectArray2[0] = "project";
                break;
            }
            case 1: {
                objectArray = objectArray2;
                objectArray2[0] = "window";
                break;
            }
        }
        objectArray[1] = "me/vespoli/secretbridge/SecretsToolWindow";
        objectArray[2] = "createToolWindowContent";
        throw new IllegalArgumentException(String.format("Argument for @NotNull parameter '%s' of %s.%s must not be null", objectArray));
    }

    static final class Panel
    extends JPanel {
        final Project project;
        final JComboBox<String> environment = new JComboBox();
        final JTextField filter = new JTextField(14);
        final DefaultTableModel itemsModel = Panel.model("Title", "Tags", "Item ID");
        final DefaultTableModel fieldsModel = Panel.model("Field", "Type", "Reference");
        final DefaultTableModel bindingsModel = Panel.model("Variable", "Group", "State", "Reference");
        final JTable items = new JTable(this.itemsModel);
        final JTable fields = new JTable(this.fieldsModel);
        final JTable bindings = new JTable(this.bindingsModel);
        final JTextArea status = new JTextArea(5, 40);
        final List<JButton> buttons = new ArrayList<JButton>();
        JsonArray itemData = new JsonArray();
        JsonArray fieldData = new JsonArray();
        String loadedItem = null;
        JsonObject plan;

        Panel(Project project) {
            super(new BorderLayout(8, 8));
            this.project = project;
            JPanel top = new JPanel(new GridLayout(0, 3, 6, 6));
            top.add(new JLabel("Environment"));
            top.add(this.environment);
            top.add(this.button("Configure", this::configure));
            top.add(this.button("Vaults", this::vaults));
            top.add(this.button("Open manifest", this::openManifest));
            top.add(this.button("Check connections", () -> this.call(Engine.req("doctor", null), r -> this.show((JsonElement)r))));
            this.add((Component)top, "North");
            JTabbedPane tabs = new JTabbedPane();
            JPanel vault = new JPanel(new BorderLayout());
            JPanel vaultTools = new JPanel(new GridLayout(0, 3, 6, 6));
            vaultTools.add(this.button("Refresh", this::refresh));
            vaultTools.add(new JLabel("Filter / group"));
            vaultTools.add(this.filter);
            this.filter.getDocument().addDocumentListener(new DocumentListener(){

                @Override
                public void insertUpdate(DocumentEvent e) {
                    Panel.this.renderItems();
                }

                @Override
                public void removeUpdate(DocumentEvent e) {
                    Panel.this.renderItems();
                }

                @Override
                public void changedUpdate(DocumentEvent e) {
                    Panel.this.renderItems();
                }
            });
            vaultTools.add(this.button("New item", this::create));
            vaultTools.add(this.button("Rename / tags", this::metadata));
            vaultTools.add(this.button("Move", this::move));
            vaultTools.add(this.button("Archive", this::archive));
            vault.add((Component)vaultTools, "North");
            JSplitPane split = new JSplitPane(0, new JScrollPane(this.items), new JScrollPane(this.fields));
            split.setResizeWeight(0.5);
            vault.add((Component)split, "Center");
            JPanel fieldTools = new JPanel(new GridLayout(0, 3, 6, 6));
            fieldTools.add(this.button("Add field", this::addField));
            fieldTools.add(this.button("Bind to application", this::bind));
            fieldTools.add(this.button("Insert reference", this::insert));
            fieldTools.add(this.button("Replace value", this::replaceValue));
            fieldTools.add(this.button("Remove field", this::removeField));
            vault.add((Component)fieldTools, "South");
            tabs.addTab("Vault", vault);
            JPanel mapped = new JPanel(new BorderLayout());
            mapped.add((Component)new JScrollPane(this.bindings), "Center");
            JPanel actions = new JPanel(new GridLayout(0, 3, 6, 6));
            actions.add(this.button("Refresh bindings", this::refreshBindings));
            actions.add(this.button("Remove binding", this::removeBinding));
            actions.add(this.button("Adopt AWS secret", this::adoptAws));
            actions.add(this.button("Create GitHub environment", this::prepareGithub));
            actions.add(this.button("Preview sync", this::preview));
            actions.add(this.button("Apply preview", this::apply));
            actions.add(this.button("Generate integration", this::generate));
            mapped.add((Component)actions, "South");
            tabs.addTab("Application / cloud", mapped);
            this.add((Component)tabs, "Center");
            this.status.setEditable(false);
            this.status.setLineWrap(true);
            this.status.setWrapStyleWord(true);
            this.status.setText("Configure a project and authenticate vendor CLIs. Only references and metadata appear here.");
            this.add((Component)new JScrollPane(this.status), "South");
            this.items.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    this.loadFields();
                }
            });
            this.environment.addActionListener(e -> {
                this.plan = null;
                this.loadedItem = null;
                this.itemData = new JsonArray();
                this.fieldsModel.setRowCount(0);
                Panel.this.renderItems();
                this.refreshBindings();
            });
            this.reloadEnvironments();
        }

        static DefaultTableModel model(String ... names) {
            return new DefaultTableModel(names, 0){

                @Override
                public boolean isCellEditable(int row, int col) {
                    return false;
                }
            };
        }

        JButton button(String label, Runnable action) {
            JButton button = new JButton(label);
            this.buttons.add(button);
            button.addActionListener(e -> action.run());
            return button;
        }

        String env() {
            return (String)this.environment.getSelectedItem();
        }

        void busy(boolean busy) {
            for (JButton b : this.buttons) {
                b.setEnabled(!busy);
            }
            this.environment.setEnabled(!busy);
            this.items.setEnabled(!busy);
            this.fields.setEnabled(!busy);
            this.bindings.setEnabled(!busy);
            this.filter.setEnabled(!busy);
        }

        void call(JsonObject req, Consumer<JsonElement> success) {
            this.busy(true);
            this.status.setText("Working\u2026 approve 1Password authorization if prompted.");
            ApplicationManager.getApplication().executeOnPooledThread(() -> {
                JsonElement result = null;
                String error = null;
                try {
                    result = Engine.request(this.project, req);
                }
                catch (Exception ex) {
                    error = ex instanceof IOException ? ex.getMessage() : "Request failed. Check configuration and authentication.";
                }
                JsonElement finalResult = result;
                String finalError = error;
                ApplicationManager.getApplication().invokeLater(() -> {
                    if (this.project.isDisposed()) {
                        return;
                    }
                    this.busy(false);
                    if (finalError != null) {
                        this.status.setText(finalError);
                        this.plan = null;
                    } else {
                        this.status.setText("Complete.");
                        success.accept(finalResult);
                    }
                });
            });
        }

        void show(JsonElement result) {
            this.status.setText(new GsonBuilder().setPrettyPrinting().create().toJson(result));
        }

        void reloadEnvironments() {
            try {
                JsonObject config = Engine.config(this.project);
                String selected = this.env();
                this.environment.removeAllItems();
                for (String name : config.getAsJsonObject("environments").keySet()) {
                    this.environment.addItem(name);
                }
                if (selected != null) {
                    this.environment.setSelectedItem(selected);
                }
            }
            catch (Exception ignored) {
                this.status.setText("Click Configure to create secretbridge.json.");
            }
        }

        String selectedItem() {
            int row = this.items.getSelectedRow();
            return row < 0 ? null : (String)this.itemsModel.getValueAt(row, 2);
        }

        JsonObject selectedField() {
            int row = this.fields.getSelectedRow();
            return row < 0 || row >= this.fieldData.size() ? null : this.fieldData.get(row).getAsJsonObject();
        }

        void renderItems() {
            this.itemsModel.setRowCount(0);
            String text = this.filter.getText().toLowerCase(Locale.ROOT);
            for (JsonElement v : this.itemData) {
                String tags;
                JsonObject item = v.getAsJsonObject();
                String title = item.get("title").getAsString();
                if (!(title + " " + (tags = item.get("tags").toString())).toLowerCase(Locale.ROOT).contains(text)) continue;
                this.itemsModel.addRow(new Object[]{title, tags, item.get("id").getAsString()});
            }
        }

        void refresh() {
            if (this.env() == null) {
                return;
            }
            this.call(Engine.req("items", this.env()), r -> {
                this.itemData = r.getAsJsonArray();
                this.loadedItem = null;
                this.fieldData = new JsonArray();
                this.fieldsModel.setRowCount(0);
                Panel.this.renderItems();
            });
        }

        void refreshBindings() {
            if (this.env() == null) {
                return;
            }
            try {
                JsonObject secrets = Engine.config(this.project).getAsJsonObject("environments").getAsJsonObject(this.env()).getAsJsonObject("secrets");
                this.bindingsModel.setRowCount(0);
                for (Map.Entry<String, JsonElement> entry : secrets.entrySet()) {
                    JsonObject s = entry.getValue().getAsJsonObject();
                    this.bindingsModel.addRow(new Object[]{entry.getKey(), s.has("group") ? s.get("group").getAsString() : "application", s.has("state") ? s.get("state").getAsString() : "present", s.has("ref") ? s.get("ref").getAsString() : ""});
                }
            }
            catch (Exception ignored) {
                this.status.setText("Configure the project first.");
            }
        }

        void loadFields() {
            String item = this.selectedItem();
            if (item == null || item.equals(this.loadedItem)) {
                return;
            }
            this.loadedItem = item;
            JsonObject req = Engine.req("fields", this.env());
            req.addProperty("item", item);
            this.call(req, r -> {
                if (!item.equals(this.selectedItem())) {
                    this.loadedItem = null;
                    this.loadFields();
                    return;
                }
                this.fieldData = r.getAsJsonObject().getAsJsonArray("fields");
                this.fieldsModel.setRowCount(0);
                for (JsonElement el : this.fieldData) {
                    JsonObject f = el.getAsJsonObject();
                    this.fieldsModel.addRow(new Object[]{f.get("label").getAsString(), f.get("type").getAsString(), f.get("ref").getAsString()});
                }
            });
        }

        boolean confirm(String message) {
            return Messages.showYesNoDialog(this.project, message, "SecretBridge", Messages.getQuestionIcon()) == 0;
        }

        String ask(String message) {
            return Messages.showInputDialog(this.project, message, "SecretBridge", null);
        }

        char[] password(String label) {
            JPasswordField field = new JPasswordField(32);
            int result = JOptionPane.showConfirmDialog(this, new Object[]{label, field}, "SecretBridge", 2, -1);
            char[] value = result == 0 ? field.getPassword() : null;
            field.setText("");
            return value;
        }

        void create() {
            if (this.env() == null) {
                return;
            }
            String title = this.ask("Item title");
            if (title == null) {
                return;
            }
            String name = this.ask("Field / application variable name (e.g. DATABASE_URL)");
            if (name == null) {
                return;
            }
            char[] value = this.password("Secret value");
            if (value == null) {
                return;
            }
            JsonObject req = Engine.req("create", this.env());
            JsonObject fs = new JsonObject();
            fs.addProperty(name, new String(value));
            Arrays.fill(value, '\u0000');
            req.add("fields", fs);
            req.addProperty("title", title);
            JsonArray tags = new JsonArray();
            tags.add("secretbridge");
            tags.add(this.env());
            req.add("tags", tags);
            this.call(req, r -> {
                req.remove("fields");
                this.plan = null;
                this.show((JsonElement)r);
                this.refresh();
            });
        }

        void metadata() {
            String item = this.selectedItem();
            if (item == null) {
                return;
            }
            String title = this.ask("New title");
            if (title == null) {
                return;
            }
            String tags = this.ask("Comma-separated tags (replaces current tags)");
            if (tags == null) {
                return;
            }
            JsonObject patch = new JsonObject();
            patch.addProperty("title", title);
            JsonArray a = new JsonArray();
            for (String tag : tags.split(",")) {
                if (tag.isBlank()) continue;
                a.add(tag.trim());
            }
            patch.add("tags", a);
            this.edit(item, patch);
        }

        void edit(String item, JsonObject patch) {
            JsonObject req = Engine.req("edit", this.env());
            req.addProperty("item", item);
            req.add("patch", patch);
            this.call(req, r -> {
                patch.remove("value");
                this.plan = null;
                this.loadedItem = null;
                this.show((JsonElement)r);
                this.loadFields();
            });
        }

        void addField() {
            String item = this.selectedItem();
            if (item == null) {
                return;
            }
            String name = this.ask("New field name (uppercase)");
            if (name == null) {
                return;
            }
            char[] value = this.password("Secret value");
            if (value == null) {
                return;
            }
            JsonObject patch = new JsonObject();
            patch.addProperty("field_name", name);
            patch.addProperty("value", new String(value));
            Arrays.fill(value, '\u0000');
            this.edit(item, patch);
        }

        void vaults() {
            this.call(Engine.req("vaults", null), r -> {
                Object[] choices = new String[r.getAsJsonArray().size() + 1];
                choices[0] = "Create new vault\u2026";
                for (int i = 0; i < r.getAsJsonArray().size(); ++i) {
                    JsonObject v = r.getAsJsonArray().get(i).getAsJsonObject();
                    choices[i + 1] = v.get("name").getAsString() + " \u2014 " + v.get("id").getAsString();
                }
                String chosen = (String)JOptionPane.showInputDialog(this, "Vaults in the selected account (IDs can be copied into Configure)", "Vaults", -1, null, choices, null);
                if (((String)choices[0]).equals(chosen)) {
                    String name = this.ask("New vault name");
                    if (name == null) {
                        return;
                    }
                    JsonObject req = Engine.req("vault-create", null);
                    req.addProperty("name", name);
                    this.call(req, this::show);
                } else if (chosen != null) {
                    this.status.setText(chosen);
                }
            });
        }

        void replaceValue() {
            JsonObject f = this.selectedField();
            String item = this.selectedItem();
            if (f == null || item == null) {
                return;
            }
            char[] value = this.password("Replacement secret value");
            if (value == null) {
                return;
            }
            JsonObject patch = new JsonObject();
            patch.addProperty("field_id", f.get("id").getAsString());
            patch.addProperty("value", new String(value));
            Arrays.fill(value, '\u0000');
            this.edit(item, patch);
        }

        void removeField() {
            JsonObject f = this.selectedField();
            String item = this.selectedItem();
            if (f == null || item == null) {
                return;
            }
            if (!this.confirm("Remove this field from 1Password? Existing references to it will stop resolving.")) {
                return;
            }
            JsonObject patch = new JsonObject();
            patch.addProperty("field_id", f.get("id").getAsString());
            patch.addProperty("remove_field", true);
            this.edit(item, patch);
        }

        void archive() {
            String item = this.selectedItem();
            if (item == null || !this.confirm("Archive this 1Password item? Cloud copies are handled separately through explicit bindings.")) {
                return;
            }
            JsonObject req = Engine.req("archive", this.env());
            req.addProperty("item", item);
            this.call(req, r -> {
                this.plan = null;
                this.refresh();
            });
        }

        void move() {
            String item = this.selectedItem();
            if (item == null) {
                return;
            }
            String target = (String)JOptionPane.showInputDialog(this, "Destination environment", "Move item", 3, null, Collections.list(new Enumeration<String>(){
                int i;

                @Override
                public boolean hasMoreElements() {
                    return this.i < environment.getItemCount();
                }

                @Override
                public String nextElement() {
                    return environment.getItemAt(this.i++);
                }
            }).toArray(), null);
            if (target == null || !this.confirm("Move item to " + target + "? Rebind any references afterward; vault permissions change.")) {
                return;
            }
            JsonObject req = Engine.req("move", this.env());
            req.addProperty("item", item);
            req.addProperty("destination", target);
            this.call(req, r -> {
                this.plan = null;
                this.show((JsonElement)r);
                this.refresh();
            });
        }

        void bind() {
            JsonObject f = this.selectedField();
            if (f == null) {
                return;
            }
            String name = this.ask("Application variable name (uppercase)");
            if (name == null) {
                return;
            }
            String group = this.ask("Group (e.g. database, messaging)");
            if (group == null) {
                return;
            }
            JsonObject req = Engine.req("bind", this.env());
            req.addProperty("name", name);
            req.addProperty("group", group);
            req.addProperty("ref", f.get("ref").getAsString());
            this.call(req, r -> {
                this.plan = null;
                this.refreshBindings();
                this.show((JsonElement)r);
            });
        }

        void insert() {
            JsonObject f = this.selectedField();
            if (f == null) {
                return;
            }
            Editor editor = FileEditorManager.getInstance(this.project).getSelectedTextEditor();
            if (editor == null) {
                return;
            }
            WriteCommandAction.runWriteCommandAction(this.project, () -> editor.getDocument().insertString(editor.getCaretModel().getOffset(), f.get("ref").getAsString()));
        }

        void removeBinding() {
            int row = this.bindings.getSelectedRow();
            if (row < 0) {
                return;
            }
            String name = (String)this.bindingsModel.getValueAt(row, 0);
            if (!this.confirm("Mark " + name + " absent? A subsequent sync preview will include removal from its configured cloud targets. The vault item is preserved.")) {
                return;
            }
            JsonObject req = Engine.req("remove-binding", this.env());
            req.addProperty("name", name);
            this.call(req, r -> {
                this.plan = null;
                this.refreshBindings();
                this.show((JsonElement)r);
            });
        }

        void adoptAws() {
            int row = this.bindings.getSelectedRow();
            if (row < 0) {
                return;
            }
            String name = (String)this.bindingsModel.getValueAt(row, 0);
            try {
                JsonObject aws = Engine.config(this.project).getAsJsonObject("environments").getAsJsonObject(this.env()).getAsJsonObject("aws");
                if (aws == null) {
                    this.status.setText("Configure an AWS target first.");
                    return;
                }
                String resource = aws.get("prefix").getAsString() + name;
                if (!this.confirm("Add project/environment ownership tags to " + resource + " in AWS account " + aws.get("account_id").getAsString() + "? This allows subsequent syncs to update or remove it. Review any existing IaC ownership first.")) {
                    return;
                }
                JsonObject req = Engine.req("adopt-aws", this.env());
                req.addProperty("name", name);
                this.plan = null;
                this.call(req, this::show);
            }
            catch (Exception e) {
                this.status.setText("Configure an AWS target first.");
            }
        }

        void prepareGithub() {
            if (this.env() == null || !this.confirm("Create the configured GitHub deployment environment if missing?")) {
                return;
            }
            this.call(Engine.req("prepare-github", this.env()), this::show);
        }

        void preview() {
            if (this.env() != null) {
                this.call(Engine.req("plan", this.env()), r -> {
                    this.plan = r.getAsJsonObject();
                    this.show((JsonElement)r);
                });
            }
        }

        void apply() {
            if (this.plan == null) {
                this.status.setText("Preview sync first.");
                return;
            }
            String details = new GsonBuilder().setPrettyPrinting().create().toJson(this.plan);
            JTextArea preview = new JTextArea(details, 24, 75);
            preview.setEditable(false);
            if (JOptionPane.showConfirmDialog(this, new JScrollPane(preview), "Apply these cloud changes?", 2) != 0) {
                return;
            }
            JsonObject req = Engine.req("apply", this.env());
            req.add("plan", this.plan);
            this.plan = null;
            this.call(req, this::show);
        }

        void generate() {
            if (this.env() == null) {
                return;
            }
            String kind = (String)JOptionPane.showInputDialog(this, "Integration", "Generate references", 3, null, new String[]{"env", "workflow-native", "workflow-1password", "terraform", "cdk", "cloudformation"}, "env");
            if (kind == null) {
                return;
            }
            JsonObject req = Engine.req("template", this.env());
            req.addProperty("kind", kind);
            this.call(req, r -> {
                JTextArea text = new JTextArea(r.getAsJsonObject().get("content").getAsString(), 25, 80);
                JOptionPane.showMessageDialog(this, new JScrollPane(text), "Copy integration template", -1);
            });
        }

        void openManifest() {
            try {
                VirtualFile file = LocalFileSystem.getInstance().refreshAndFindFileByPath(Engine.manifest(this.project).toString());
                if (file != null) {
                    FileEditorManager.getInstance(this.project).openFile(file, true);
                }
            }
            catch (Exception e) {
                this.status.setText("Configure the project first.");
            }
        }

        void configure() {
            Object[][] rows;
            JTextField account = new JTextField();
            JTextField projectName = new JTextField(this.project.getName());
            JTextField envName = new JTextField(this.env() == null ? "development" : this.env());
            JTextField vault = new JTextField();
            JTextField repo = new JTextField();
            JTextField ghEnv = new JTextField();
            JTextField organization = new JTextField();
            JTextField allowedRepos = new JTextField();
            JComboBox<String> scope = new JComboBox<String>(new String[]{"none", "repository", "environment", "organization"});
            JTextField profile = new JTextField();
            JTextField region = new JTextField("us-east-1");
            JTextField accountId = new JTextField();
            JTextField prefix = new JTextField();
            try {
                JsonObject config = Engine.config(this.project);
                account.setText(config.get("account").getAsString());
                projectName.setText(config.get("project").getAsString());
                JsonObject selected = config.getAsJsonObject("environments").getAsJsonObject(envName.getText());
                if (selected != null) {
                    vault.setText(selected.get("vault").getAsString());
                    if (selected.has("github")) {
                        JsonObject gh = selected.getAsJsonObject("github");
                        scope.setSelectedItem(gh.get("scope").getAsString());
                        if (gh.has("repository")) {
                            repo.setText(gh.get("repository").getAsString());
                        }
                        if (gh.has("environment")) {
                            ghEnv.setText(gh.get("environment").getAsString());
                        }
                        if (gh.has("organization")) {
                            organization.setText(gh.get("organization").getAsString());
                        }
                        if (gh.has("repositories")) {
                            ArrayList<String> values = new ArrayList<String>();
                            for (JsonElement value : gh.getAsJsonArray("repositories")) {
                                values.add(value.getAsString());
                            }
                            allowedRepos.setText(String.join((CharSequence)",", values));
                        }
                    }
                    if (selected.has("aws")) {
                        JsonObject aws = selected.getAsJsonObject("aws");
                        profile.setText(aws.get("profile").getAsString());
                        region.setText(aws.get("region").getAsString());
                        accountId.setText(aws.get("account_id").getAsString());
                        prefix.setText(aws.get("prefix").getAsString());
                    }
                }
            }
            catch (Exception config) {
                // empty catch block
            }
            JPanel form = new JPanel(new GridLayout(0, 2, 8, 4));
            for (Object[] row : rows = new Object[][]{{"1Password account ID / shorthand", account}, {"Project name", projectName}, {"Environment name", envName}, {"Vault ID (separate vault per environment)", vault}, {"GitHub scope", scope}, {"GitHub owner/repository", repo}, {"GitHub deployment environment", ghEnv}, {"GitHub organization", organization}, {"Organization repository allowlist", allowedRepos}, {"AWS profile (blank disables AWS)", profile}, {"AWS region", region}, {"AWS account ID", accountId}, {"AWS secret prefix ending in /", prefix}}) {
                form.add(new JLabel((String)row[0]));
                form.add((Component)row[1]);
            }
            JButton pick = new JButton("Select / create vault");
            form.add(new JLabel("Vault browser"));
            form.add(pick);
            pick.addActionListener(event -> {
                JsonObject req = Engine.req("bootstrap-vaults", null);
                req.addProperty("account", account.getText());
                JsonObject tools = new JsonObject();
                tools.addProperty("op", BridgeSettings.get().getState().op);
                req.add("tools", tools);
                this.call(req, r -> {
                    Object[] options = new String[r.getAsJsonArray().size() + 1];
                    options[0] = "Create new vault\u2026";
                    for (int i = 0; i < r.getAsJsonArray().size(); ++i) {
                        JsonObject v2 = r.getAsJsonArray().get(i).getAsJsonObject();
                        options[i + 1] = v2.get("name").getAsString() + " \u2014 " + v2.get("id").getAsString();
                    }
                    String chosen = (String)JOptionPane.showInputDialog(form, "Select environment vault", "Vaults", -1, null, options, null);
                    if (((String)options[0]).equals(chosen)) {
                        String name = this.ask("New vault name");
                        if (name == null) {
                            return;
                        }
                        JsonObject create = Engine.req("bootstrap-vault-create", null);
                        create.addProperty("account", account.getText());
                        create.add("tools", tools);
                        create.addProperty("name", name);
                        this.call(create, v -> vault.setText(v.getAsJsonObject().get("id").getAsString()));
                    } else if (chosen != null) {
                        vault.setText(chosen.substring(chosen.lastIndexOf(" \u2014 ") + 3));
                    }
                });
            });
            if (JOptionPane.showConfirmDialog(this, form, "Configure project / add environment", 2, -1) != 0) {
                return;
            }
            try {
                JsonObject config;
                try {
                    config = Engine.config(this.project);
                }
                catch (Exception e) {
                    config = new JsonObject();
                    config.addProperty("version", 1);
                    config.add("environments", new JsonObject());
                }
                config.addProperty("project", projectName.getText());
                config.addProperty("account", account.getText());
                JsonObject tools = new JsonObject();
                BridgeSettings.Data settings = BridgeSettings.get().getState();
                tools.addProperty("op", settings.op);
                tools.addProperty("gh", settings.gh);
                tools.addProperty("aws", settings.aws);
                config.add("tools", tools);
                JsonObject env = new JsonObject();
                env.addProperty("vault", vault.getText());
                JsonObject old = config.getAsJsonObject("environments").getAsJsonObject(envName.getText());
                env.add("secrets", old != null && old.has("secrets") ? old.get("secrets") : new JsonObject());
                String chosen = (String)scope.getSelectedItem();
                if (!"none".equals(chosen)) {
                    JsonObject gh = new JsonObject();
                    gh.addProperty("scope", chosen);
                    if ("organization".equals(chosen)) {
                        gh.addProperty("organization", organization.getText());
                        JsonArray repos = new JsonArray();
                        for (String r2 : allowedRepos.getText().split(",")) {
                            if (r2.isBlank()) continue;
                            repos.add(r2.trim());
                        }
                        gh.add("repositories", repos);
                    } else {
                        gh.addProperty("repository", repo.getText());
                        if ("environment".equals(chosen)) {
                            gh.addProperty("environment", ghEnv.getText());
                        }
                    }
                    if (old != null && old.has("github") && old.getAsJsonObject("github").has("host")) {
                        gh.add("host", old.getAsJsonObject("github").get("host"));
                    }
                    env.add("github", gh);
                }
                if (!profile.getText().isBlank()) {
                    JsonObject aws = new JsonObject();
                    aws.addProperty("profile", profile.getText());
                    aws.addProperty("region", region.getText());
                    aws.addProperty("account_id", accountId.getText());
                    aws.addProperty("prefix", prefix.getText());
                    if (old != null && old.has("aws")) {
                        JsonObject prior = old.getAsJsonObject("aws");
                        for (String key : new String[]{"kms_key_id", "recovery_days"}) {
                            if (!prior.has(key)) continue;
                            aws.add(key, prior.get(key));
                        }
                    }
                    env.add("aws", aws);
                }
                config.getAsJsonObject("environments").add(envName.getText(), env);
                JsonObject validate = Engine.req("validate-config", null);
                validate.add("config", config);
                JsonObject ready = config;
                this.call(validate, r -> {
                    try {
                        Engine.save(this.project, ready);
                        this.reloadEnvironments();
                        this.environment.setSelectedItem(envName.getText());
                        this.plan = null;
                        this.status.setText("Project configured. Refresh vault contents to select and bind fields. Use Open manifest for advanced options.");
                    }
                    catch (Exception error) {
                        this.status.setText("Could not save configuration. Check project path.");
                    }
                });
            }
            catch (Exception e) {
                this.status.setText("Could not save configuration. Check project path.");
            }
        }
    }
}
