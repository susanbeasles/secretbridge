package me.vespoli.secretbridge;

import com.google.gson.JsonObject;
import com.intellij.openapi.project.Project;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class EngineContract {
    private static Project project(String base) {
        return (Project) Proxy.newProxyInstance(Project.class.getClassLoader(), new Class<?>[]{Project.class},
            (proxy, method, args) -> method.getName().equals("getBasePath") ? base : null);
    }
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]);
        Project project = project(directory.toString());
        JsonObject config = new JsonObject();
        config.addProperty("reference", "op://disposable/example/credential");
        Engine.save(project, config);
        check(Engine.config(project).equals(config), "Saved manifest did not round-trip");
        Path target = directory.resolve("retained.json");
        Files.move(Engine.manifest(project), target);
        Files.createSymbolicLink(Engine.manifest(project), target);
        try { Engine.save(project, new JsonObject()); throw new AssertionError("Symlink accepted"); }
        catch (IOException expected) { check(Files.readString(target).contains("op://disposable"), "Symlink target changed"); }
        try { Engine.manifest(project(null)); throw new AssertionError("Missing project accepted"); }
        catch (IOException expected) { }
        check(Engine.req("preview", "dev").get("environment").getAsString().equals("dev"), "Environment lost");
        check(!Engine.req("doctor", null).has("environment"), "Unrequested environment inserted");
        check(new String(Engine.read(new ByteArrayInputStream("fixture".getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8).equals("fixture"), "Output bytes lost");
        check(Engine.read(new InputStream() { public int read() throws IOException { throw new IOException("fixture-failure"); } }).length == 0, "Failed stream accepted");
        try (var paths = Files.list(directory)) {
            check(paths.noneMatch(p -> p.getFileName().toString().startsWith(".secretbridge-")), "Temporary manifest retained");
        }
        System.out.println("PASS: recovered frontend manifest round-trip, symlink rejection, missing-project denial and stream handling; no live provider operations");
    }
}
