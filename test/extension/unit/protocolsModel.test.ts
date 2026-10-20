import * as assert from "node:assert/strict";
import {
  effectiveSwitch,
  normalizeSwitches,
  sameSwitches,
  switchDescription,
  switchOverrides,
  switchSummary,
} from "../../../src/protocolsModel";

suite("enabled protocols", () => {
  test("normalizeSwitches keeps valid names with booleans, sorted", () => {
    assert.deepEqual(
      normalizeSwitches({ sip: false, "bad name": true, http: "no", rtp_udp: true, "ip.v4": 1 }),
      { rtp_udp: true, sip: false },
    );
    assert.deepEqual(normalizeSwitches(["sip"]), {});
    assert.deepEqual(normalizeSwitches(undefined), {});
    assert.ok(sameSwitches({ a: true, b: false }, { b: false, a: true }));
    assert.ok(!sameSwitches({ a: true }, { a: false }));
    assert.ok(!sameSwitches({ a: true }, { a: true, b: true }));
  });

  test("a protocol's state: here, then Wireshark, then the default", () => {
    assert.deepEqual(effectiveSwitch("http", true, {}, {}), { on: true, source: "default" });
    assert.deepEqual(effectiveSwitch("http", true, { http: false }, {}), {
      on: false,
      source: "wireshark",
    });
    assert.deepEqual(effectiveSwitch("http", true, { http: false }, { http: true }), {
      on: true,
      source: "here",
    });
    assert.equal(switchDescription("http", "here", false), "http · disabled here");
    assert.equal(switchDescription("dns", "wireshark", true), "dns · enabled in Wireshark");
    assert.equal(switchDescription("tcp", "default", true), "tcp");
  });

  test("only what differs from Wireshark is stored; unlisted overrides stay", () => {
    const listed = [
      { name: "http", default: true },
      { name: "dns", default: true },
      { name: "communityid", default: false },
    ];
    const wireshark = { dns: false };
    // Everything as Wireshark has it: nothing to store, except the Lua
    // protocol that isn't listed now.
    assert.deepEqual(
      switchOverrides(listed, wireshark, { myproto: false, http: false }, new Set(["http"])),
      { myproto: false },
    );
    // HTTP off, DNS back on (Wireshark disables it), Community ID on.
    assert.deepEqual(switchOverrides(listed, wireshark, {}, new Set(["dns", "communityid"])), {
      communityid: true,
      dns: true,
      http: false,
    });
  });

  test("switchSummary counts what is switched here", () => {
    assert.equal(switchSummary({}, {}), "Wireshark's settings");
    assert.equal(
      switchSummary({ http: false, dns: false, communityid: true }, { rtp_udp: true }),
      "2 protocols disabled, 1 protocol enabled, 1 heuristic enabled",
    );
  });
});
