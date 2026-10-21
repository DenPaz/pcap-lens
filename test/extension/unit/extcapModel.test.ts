import * as assert from "node:assert/strict";
import {
  ExtcapArg,
  captureOptions,
  defaultValue,
  groupArgs,
  initialValues,
  missingRequired,
  storableValues,
  validateValue,
  valueLabel,
} from "../../../src/extcapModel";

const arg = (a: Partial<ExtcapArg> & Pick<ExtcapArg, "call" | "type">): ExtcapArg => ({
  number: 0,
  required: false,
  mustexist: false,
  values: [],
  ...a,
});

// sshdump's options, shortened.
const HOST = arg({ call: "--remote-host", type: "string", required: true, group: "Server" });
const PORT = arg({ call: "--remote-port", type: "unsigned", default: "22", range: "1,65535" });
const PASSWORD = arg({ call: "--remote-password", type: "password", group: "Authentication" });
const NOPROM = arg({ call: "--remote-noprom", type: "boolflag", display: "No promiscuous mode" });
const PRIV = arg({
  call: "--remote-priv",
  type: "radio",
  values: [
    { value: "none", display: "none", default: true },
    { value: "doas -n", display: "doas", default: false },
  ],
});
const ARGS = [HOST, PORT, PASSWORD, NOPROM, PRIV];

suite("extcapModel", () => {
  test("defaults: the helper's, else the default choice, else off or empty", () => {
    assert.deepEqual(ARGS.map(defaultValue), ["", "22", "", "false", "none"]);
  });

  test("values start from the stored ones, never a stored password", () => {
    const values = initialValues(ARGS, {
      "--remote-host": "box",
      "--remote-password": "leaked",
      "--remote-port": 2222,
      "--gone": "x",
    });
    assert.deepEqual(values, {
      "--remote-host": "box",
      "--remote-port": "22",
      "--remote-password": "",
      "--remote-noprom": "false",
      "--remote-priv": "none",
    });
    assert.deepEqual(initialValues(ARGS, undefined)["--remote-port"], "22");
    const stored = storableValues(ARGS, { ...values, "--remote-password": "secret" });
    assert.equal(stored["--remote-password"], undefined);
    assert.equal(stored["--remote-host"], "box");
  });

  test("values are checked by type", () => {
    assert.equal(validateValue(HOST, ""), "remote-host is required");
    assert.equal(validateValue(PORT, ""), undefined);
    assert.equal(validateValue(PORT, "x"), "A whole number");
    assert.equal(validateValue(PORT, "0"), "From 1 to 65535");
    assert.equal(validateValue(PORT, "2222"), undefined);
    assert.equal(validateValue(arg({ call: "--n", type: "unsigned" }), "-1"), "Zero or more");
    assert.equal(validateValue(arg({ call: "--d", type: "double" }), "0.5"), undefined);
    assert.equal(validateValue(NOPROM, "yes"), "true or false");
    assert.equal(validateValue(PRIV, "sudo"), "One of: none, doas");
    assert.equal(validateValue(HOST, "a\nb"), "A single line, please");
  });

  test("required options without a value block the capture", () => {
    const values = initialValues(ARGS, {});
    assert.deepEqual(
      missingRequired(ARGS, values).map((a) => a.call),
      ["--remote-host"],
    );
    assert.deepEqual(missingRequired(ARGS, { ...values, "--remote-host": "box" }), []);
  });

  test("labels hide passwords and name choices", () => {
    assert.equal(valueLabel(HOST, ""), "(required)");
    assert.equal(valueLabel(PASSWORD, ""), "(not set)");
    assert.equal(valueLabel(PASSWORD, "secret"), "••••••");
    assert.equal(valueLabel(NOPROM, "true"), "On");
    assert.equal(valueLabel(PRIV, "doas -n"), "doas");
    assert.equal(valueLabel(PORT, "22"), "22");
  });

  test("capture options carry every option, so Wireshark's saved ones don't apply", () => {
    assert.deepEqual(
      captureOptions(ARGS, { "--remote-host": " box ", "--remote-noprom": "false" }),
      {
        "--remote-host": "box",
        "--remote-port": "22",
        "--remote-password": "",
        "--remote-noprom": "false",
        "--remote-priv": "none",
      },
    );
  });

  test("options keep the helper's groups and order", () => {
    assert.deepEqual(
      groupArgs(ARGS).map(([g, a]) => [g, a.map((x) => x.call)]),
      [
        ["Server", ["--remote-host"]],
        ["", ["--remote-port", "--remote-noprom", "--remote-priv"]],
        ["Authentication", ["--remote-password"]],
      ],
    );
  });
});
