import * as assert from "node:assert/strict";
import {
  ProtocolPref,
  effectivePref,
  prefLabel,
  prefSettingValue,
  prefText,
  samePrefs,
  validatePrefValue,
  withPref,
} from "../../../src/prefsModel";

const pref = (p: Partial<ProtocolPref> & Pick<ProtocolPref, "type">): ProtocolPref => ({
  name: "tcp.something",
  description: "",
  default: "",
  wireshark: "",
  ...p,
});

const SEQ = pref({
  name: "tcp.analyze_sequence_numbers",
  type: "bool",
  default: "TRUE",
  wireshark: "TRUE",
});
const SCALING = pref({
  name: "tcp.default_window_scaling",
  type: "enum",
  choices: ["Not known", "0 (no scaling)", "1 (multiply by 2)"],
  default: "Not known",
  wireshark: "Not known",
});

suite("prefsModel", () => {
  test("labels from preference names", () => {
    assert.equal(prefLabel("tcp.analyze_sequence_numbers"), "Analyze sequence numbers");
    assert.equal(prefLabel("http.tls.port"), "Tls port");
    assert.equal(prefLabel("noprefix"), "Noprefix");
  });

  test("the value in effect: the setting, else Wireshark's, else the default", () => {
    assert.deepEqual(effectivePref(SEQ, {}), { value: "TRUE", source: "default" });
    assert.deepEqual(effectivePref({ ...SEQ, wireshark: "FALSE" }, {}), {
      value: "FALSE",
      source: "wireshark",
    });
    assert.deepEqual(effectivePref(SEQ, { "tcp.analyze_sequence_numbers": false }), {
      value: "FALSE",
      source: "setting",
    });
    // Booleans compare without case ("true" in a user's preferences file).
    assert.equal(effectivePref({ ...SEQ, wireshark: "true" }, {}).source, "default");
  });

  test("values are checked by type", () => {
    assert.equal(validatePrefValue(SEQ, "false"), undefined);
    assert.match(validatePrefValue(SEQ, "yes") ?? "", /TRUE or FALSE/);
    assert.equal(validatePrefValue(pref({ type: "uint" }), "1500"), undefined);
    assert.ok(validatePrefValue(pref({ type: "uint" }), "-1"));
    assert.equal(validatePrefValue(pref({ type: "hex" }), "0x1F"), undefined);
    assert.ok(validatePrefValue(pref({ type: "hex" }), "0xZZ"));
    assert.equal(validatePrefValue(pref({ type: "range" }), "1-20, 30-40,80"), undefined);
    assert.equal(validatePrefValue(pref({ type: "range" }), ""), undefined);
    assert.ok(validatePrefValue(pref({ type: "range" }), "1-"));
    assert.equal(validatePrefValue(pref({ type: "color" }), "fce94f"), undefined);
    assert.ok(validatePrefValue(pref({ type: "color" }), "#fce94f"));
    assert.equal(validatePrefValue(SCALING, "1 (MULTIPLY BY 2)"), undefined);
    assert.match(validatePrefValue(SCALING, "3") ?? "", /One of: Not known/);
    assert.equal(validatePrefValue(pref({ type: "string" }), "anything"), undefined);
    assert.ok(validatePrefValue(pref({ type: "string" }), "two\nlines"));
  });

  test("setting values: booleans, numbers, tshark's spelling of a choice", () => {
    assert.equal(prefSettingValue(SEQ, "FALSE"), false);
    assert.equal(prefSettingValue(pref({ type: "uint" }), " 1500 "), 1500);
    assert.equal(prefSettingValue(SCALING, "1 (MULTIPLY BY 2)"), "1 (multiply by 2)");
    assert.equal(prefSettingValue(pref({ type: "file" }), " /tmp/keys.log "), "/tmp/keys.log");
    assert.equal(prefText(false), "FALSE");
    assert.equal(prefText(1500), "1500");
  });

  test("an override equal to Wireshark's value is removed, not stored", () => {
    const others = { "ip.defragment": false };
    assert.deepEqual(withPref(others, SEQ, false), {
      ...others,
      "tcp.analyze_sequence_numbers": false,
    });
    assert.deepEqual(withPref({ ...others, "tcp.analyze_sequence_numbers": false }, SEQ, true), {
      ...others,
    });
    assert.deepEqual(withPref({ "tcp.analyze_sequence_numbers": false }, SEQ, undefined), {});
    // Wireshark's own value differs from the default: setting the default is a change.
    const changed = { ...SEQ, wireshark: "FALSE" };
    assert.deepEqual(withPref({}, changed, true), { "tcp.analyze_sequence_numbers": true });
  });

  test("samePrefs compares as tshark reads the values", () => {
    assert.ok(samePrefs({ a: true, b: "x" }, { b: "x", a: "TRUE" }));
    assert.ok(!samePrefs({ a: true }, { a: false }));
    assert.ok(!samePrefs({ a: true }, { a: true, b: 1 }));
    assert.ok(samePrefs({}, {}));
  });
});
