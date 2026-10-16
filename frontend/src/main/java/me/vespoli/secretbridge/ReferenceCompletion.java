/*
 * Decompiled with CFR 0.152.
 */
package me.vespoli.secretbridge;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.intellij.codeInsight.completion.CompletionContributor;
import com.intellij.codeInsight.completion.CompletionParameters;
import com.intellij.codeInsight.completion.CompletionProvider;
import com.intellij.codeInsight.completion.CompletionResultSet;
import com.intellij.codeInsight.completion.CompletionType;
import com.intellij.codeInsight.lookup.LookupElementBuilder;
import com.intellij.openapi.editor.Document;
import com.intellij.patterns.PlatformPatterns;
import com.intellij.util.ProcessingContext;
import java.util.Map;
import me.vespoli.secretbridge.Engine;
import org.jetbrains.annotations.NotNull;

public final class ReferenceCompletion
extends CompletionContributor {
    public ReferenceCompletion() {
        this.extend(CompletionType.BASIC, PlatformPatterns.psiElement(), new CompletionProvider<CompletionParameters>(){

            @Override
            protected void addCompletions(@NotNull CompletionParameters params, @NotNull ProcessingContext context, @NotNull CompletionResultSet result) {
                if (params == null) {
                    $$$reportNull$$$0(0);
                }
                if (context == null) {
                    $$$reportNull$$$0(1);
                }
                if (result == null) {
                    $$$reportNull$$$0(2);
                }
                Document document = params.getEditor().getDocument();
                int offset = params.getOffset();
                String preceding = document.getText().substring(Math.max(0, offset - 256), offset);
                int start = preceding.lastIndexOf("op://");
                if (start < 0) {
                    return;
                }
                String prefix = preceding.substring(start);
                if (prefix.contains("\n") || prefix.contains("\"") || prefix.contains("'")) {
                    return;
                }
                CompletionResultSet prefixed = result.withPrefixMatcher(prefix);
                try {
                    JsonObject envs = Engine.config(params.getPosition().getProject()).getAsJsonObject("environments");
                    for (Map.Entry<String, JsonElement> env : envs.entrySet()) {
                        JsonObject secrets = env.getValue().getAsJsonObject().getAsJsonObject("secrets");
                        for (Map.Entry<String, JsonElement> entry : secrets.entrySet()) {
                            JsonObject spec = entry.getValue().getAsJsonObject();
                            if (!spec.has("ref") || spec.has("state") && spec.get("state").getAsString().equals("absent")) continue;
                            prefixed.addElement(LookupElementBuilder.create(spec.get("ref").getAsString()).withTypeText(env.getKey()).withTailText(" " + entry.getKey()));
                        }
                    }
                }
                catch (Exception exception) {
                    // empty catch block
                }
            }

            private static /* synthetic */ void $$$reportNull$$$0(int n) {
                Object[] objectArray;
                Object[] objectArray2 = new Object[3];
                switch (n) {
                    default: {
                        objectArray = objectArray2;
                        objectArray2[0] = "params";
                        break;
                    }
                    case 1: {
                        objectArray = objectArray2;
                        objectArray2[0] = "context";
                        break;
                    }
                    case 2: {
                        objectArray = objectArray2;
                        objectArray2[0] = "result";
                        break;
                    }
                }
                objectArray[1] = "me/vespoli/secretbridge/ReferenceCompletion$1";
                objectArray[2] = "addCompletions";
                throw new IllegalArgumentException(String.format("Argument for @NotNull parameter '%s' of %s.%s must not be null", objectArray));
            }
        });
    }
}
