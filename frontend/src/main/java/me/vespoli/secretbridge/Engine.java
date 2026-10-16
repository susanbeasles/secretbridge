/*
 * Decompiled with CFR 0.152.
 */
package me.vespoli.secretbridge;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.openapi.project.Project;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import me.vespoli.secretbridge.BridgeSettings;

final class Engine {
    private static Path script;

    Engine() {
    }

    static synchronized Path script() throws IOException {
        if (script == null || !Files.exists(script, new LinkOption[0])) {
            script = Files.createTempFile("secretbridge-engine-", ".py", new FileAttribute[0]);
            try (InputStream input = Engine.class.getResourceAsStream("/secretbridge.py");){
                if (input == null) {
                    throw new IOException("Bundled engine missing");
                }
                Files.copy(input, script, StandardCopyOption.REPLACE_EXISTING);
            }
            script.toFile().deleteOnExit();
        }
        return script;
    }

    static Path manifest(Project project) throws IOException {
        String base = project.getBasePath();
        if (base == null) {
            throw new IOException("Open a local project first");
        }
        return Path.of(base, "secretbridge.json");
    }

    static GeneralCommandLine command(Project project, String ... args) throws IOException {
        return new GeneralCommandLine(BridgeSettings.get().getState().python, "-I", Engine.script().toString(), "--manifest", Engine.manifest(project).toString()).withParameters(args).withWorkDirectory(project.getBasePath()).withCharset(StandardCharsets.UTF_8);
    }

    static JsonObject config(Project project) throws IOException {
        return JsonParser.parseString(Files.readString(Engine.manifest(project))).getAsJsonObject();
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    static JsonElement request(Project project, JsonObject request) throws Exception {
        Process proc = Engine.command(project, "rpc").createProcess();
        CompletableFuture<byte[]> output = CompletableFuture.supplyAsync(() -> Engine.read(proc.getInputStream()));
        CompletableFuture<byte[]> error = CompletableFuture.supplyAsync(() -> Engine.read(proc.getErrorStream()));
        try {
            byte[] payload = request.toString().getBytes(StandardCharsets.UTF_8);
            try (OutputStream input = proc.getOutputStream();){
                input.write(payload);
            }
            finally {
                Arrays.fill(payload, (byte)0);
                request.remove("fields");
                if (request.has("patch")) {
                    request.getAsJsonObject("patch").remove("value");
                }
            }
            if (!proc.waitFor(600L, TimeUnit.SECONDS)) {
                throw new IOException("Request timed out; preview cloud state before retrying");
            }
            JsonObject response = JsonParser.parseString(new String(output.get(), StandardCharsets.UTF_8)).getAsJsonObject();
            error.get();
            if (!response.has("ok") || !response.get("ok").getAsBoolean()) {
                throw new IOException(response.has("error") ? response.get("error").getAsString() : "Operation failed");
            }
            JsonElement jsonElement = response.get("result");
            return jsonElement;
        }
        finally {
            if (proc.isAlive()) {
                proc.destroyForcibly();
            }
        }
    }

    static byte[] read(InputStream stream) {
        try (InputStream input = stream) {
            return input.readAllBytes();
        } catch (IOException e) {
            return new byte[0];
        }
    }

    static JsonObject req(String action, String env) {
        JsonObject req = new JsonObject();
        req.addProperty("action", action);
        if (env != null) {
            req.addProperty("environment", env);
        }
        return req;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    static void save(Project project, JsonObject config) throws IOException {
        Path manifest = Engine.manifest(project);
        if (Files.isSymbolicLink(manifest)) {
            throw new IOException("Manifest cannot be a symlink");
        }
        Path tmp = Files.createTempFile(manifest.getParent(), ".secretbridge-", ".tmp", new FileAttribute[0]);
        try {
            Files.writeString(tmp, (CharSequence)(new GsonBuilder().setPrettyPrinting().create().toJson(config) + "\n"), new OpenOption[0]);
            Files.move(tmp, manifest, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        }
        finally {
            Files.deleteIfExists(tmp);
        }
    }
}
