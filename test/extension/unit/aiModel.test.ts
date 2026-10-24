import * as assert from "node:assert/strict";
import {
  ModelInfo,
  UnusableModelError,
  automaticModel,
  modelItems,
  modelLabel,
  modelSelector,
  unavailableMessage,
  unusableMessage,
  unusableReason,
} from "../../../src/aiModel";

const models: ModelInfo[] = [
  { id: "llama3", name: "Llama 3", vendor: "ollama", family: "llama3", maxInputTokens: 8192 },
  { id: "gpt-4o", name: "GPT-4o", vendor: "copilot", family: "gpt-4o", maxInputTokens: 64000 },
  {
    id: "claude",
    name: "Claude Sonnet",
    vendor: "copilot",
    family: "claude-sonnet",
    maxInputTokens: 80000,
  },
];

suite("AI language model choice", () => {
  test("the setting picks Copilot (automatic) or exactly the chosen model", () => {
    assert.deepEqual(modelSelector(""), { vendor: "copilot" });
    assert.deepEqual(modelSelector("  "), { vendor: "copilot" });
    assert.deepEqual(modelSelector(" llama3 "), { id: "llama3" }, "never another vendor instead");
  });

  test("picker rows: Automatic, then each vendor's models, the one in use marked", () => {
    const rows = modelItems(models, "llama3");
    assert.deepEqual(
      rows.map((r) => (r.separator ? `— ${r.label}` : r.label)),
      ["Automatic", "— GitHub Copilot", "Claude Sonnet", "GPT-4o", "— ollama", "Llama 3"],
    );
    assert.equal(rows.find((r) => r.picked)?.id, "llama3");
    assert.match(rows.find((r) => r.id === "llama3")?.description ?? "", /in use/);
    assert.equal(rows[0].id, "", "Automatic clears the setting");
    assert.ok(modelItems(models, "")[0].picked);
    assert.match(rows.find((r) => r.id === "gpt-4o")?.detail ?? "", /64,000 input tokens/);
  });

  test("a chosen model that is gone stays listed", () => {
    const rows = modelItems(models, "gone-model");
    const last = rows.at(-1);
    assert.equal(last?.id, "gone-model");
    assert.ok(last?.picked);
    assert.equal(rows.at(-2)?.separator, true);
  });

  test("labels and why AI help can't answer", () => {
    assert.equal(modelLabel(models[1]), "GPT-4o (GitHub Copilot)");
    assert.equal(modelLabel(models[0]), "Llama 3 (ollama)");
    assert.match(unavailableMessage("", false), /GitHub Copilot.*Choose Language Model/);
    assert.match(unavailableMessage("llama3", false), /"llama3".*isn't available/);
    assert.match(unavailableMessage("llama3", true), /not allowed/);
  });

  test("models that can't serve extensions: the reason, the message, the automatic choice", () => {
    // Seen with Copilot: a model kept for VS Code's chat, and Copilot CLI's
    // "Auto", which answered with nothing.
    const core = new Error("Model gpt-5.6-luna is only available to VS Code core.");
    assert.equal(unusableReason(core), "core-only");
    assert.equal(unusableReason(new Error("rate limited")), undefined);
    assert.equal(unusableReason(undefined, " \n"), "empty");
    assert.equal(unusableReason(undefined, "OK"), undefined);
    assert.equal(unusableReason(undefined), undefined);

    const err = new UnusableModelError("Auto (copilotcli)", "auto", "empty");
    assert.match(err.message, /Auto \(copilotcli\): empty answer/);
    assert.match(
      unusableMessage("GPT-5.6 Luna (GitHub Copilot)", "core-only", false),
      /^GPT-5\.6 Luna \(GitHub Copilot\) is reserved for VS Code's own chat.*Pick another model/,
    );
    assert.match(
      unusableMessage("X", "empty", true),
      /^X sent an empty answer\. Try again: .*another GitHub Copilot model/,
    );

    const copilot = [{ id: "a" }, { id: "b" }];
    assert.equal(automaticModel(copilot, new Set())?.id, "a");
    assert.equal(automaticModel(copilot, new Set(["a"]))?.id, "b");
    // Every one failed: the first again (the user may have fixed it).
    assert.equal(automaticModel(copilot, new Set(["a", "b"]))?.id, "a");
    assert.equal(automaticModel([], new Set()), undefined);
  });
});
