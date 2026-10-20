import * as assert from "node:assert/strict";
import {
  DecryptionKey,
  keyFile,
  keyLabel,
  normalizeKeys,
  validate,
  withKey,
} from "../../../src/decryptionKeys";

suite("decryption keys", () => {
  test("normalizeKeys keeps well-formed keys and fills ESP defaults", () => {
    assert.deepEqual(
      normalizeKeys([
        { type: "wep", key: "0a1b2c3d4e" },
        { type: "wpa-pwd", password: "secret123", ssid: "" },
        { type: "rsa", file: "/k.pem" },
        { type: "ssh" },
        { type: "esp", encryption: "AES-CTR [RFC3686]", encryptionKey: "00" },
        { type: "nonsense" },
        "junk",
      ]),
      [
        { type: "wep", key: "0a1b2c3d4e" },
        { type: "wpa-pwd", password: "secret123", ssid: undefined },
        { type: "rsa", file: "/k.pem", password: undefined },
        {
          type: "esp",
          protocol: "IPv4",
          src: "*",
          dst: "*",
          spi: "*",
          encryption: "AES-CTR [RFC3686]",
          encryptionKey: "00",
          authentication: "NULL",
          authenticationKey: undefined,
        },
      ],
    );
    assert.deepEqual(normalizeKeys({ type: "wep" }), []);
  });

  test("labels name a key without giving its secret away", () => {
    assert.equal(keyLabel({ type: "wep", key: "0a:1b:2c:3d:4e" }), "WEP key 0a1b… (5 bytes)");
    assert.equal(
      keyLabel({ type: "wpa-pwd", password: "secret123", ssid: "Home" }),
      'WPA passphrase for "Home"',
    );
    assert.equal(
      keyLabel({ type: "wpa-pwd", password: "secret123" }),
      "WPA passphrase (any network)",
    );
    assert.equal(
      keyLabel({ type: "rsa", file: "/keys/server.pem", password: "x" }),
      "RSA private key server.pem (with password)",
    );
    assert.equal(keyLabel({ type: "ssh", file: "C:\\keys\\ssh.log" }), "SSH key log ssh.log");
    const esp: DecryptionKey = {
      type: "esp",
      protocol: "IPv4",
      src: "10.8.0.1",
      dst: "10.8.0.2",
      spi: "0x1001",
      encryption: "AES-CTR [RFC3686]",
      encryptionKey: "00112233",
      authentication: "NULL",
    };
    assert.equal(keyLabel(esp), "ESP SA 10.8.0.1 → 10.8.0.2, SPI 0x1001 (AES-CTR)");
    for (const key of [esp, { type: "wep", key: "0a1b2c3d4e" } as DecryptionKey]) {
      assert.ok(!keyLabel(key).includes("2c3d"), "no secret in the label");
    }
    assert.equal(keyFile({ type: "kerberos", file: "/k.keytab" }), "/k.keytab");
    assert.equal(keyFile(esp), undefined);
  });

  test("withKey adds, replaces, drops duplicates and keeps one file per preference", () => {
    const wep: DecryptionKey = { type: "wep", key: "0a1b2c3d4e" };
    const ssh: DecryptionKey = { type: "ssh", file: "/a.keys" };
    const rsa: DecryptionKey = { type: "rsa", file: "/a.pem" };
    assert.deepEqual(withKey([wep], ssh), [wep, ssh]);
    assert.deepEqual(withKey([wep, ssh], { type: "ssh", file: "/b.keys" }), [
      wep,
      { type: "ssh", file: "/b.keys" },
    ]);
    assert.deepEqual(withKey([wep, rsa], { type: "rsa", file: "/b.pem" }), [
      wep,
      rsa,
      { type: "rsa", file: "/b.pem" },
    ]);
    assert.deepEqual(withKey([wep, ssh], wep), [ssh, wep]);
    assert.deepEqual(withKey([wep, ssh], rsa, 0), [rsa, ssh]);
  });

  test("input checks", () => {
    assert.equal(validate.hex("0a:1b:2c:3d:4e", [5, 13, 16]), undefined);
    assert.match(validate.hex("0a1b", [5, 13, 16]) ?? "", /10, 26, 32/);
    assert.match(validate.hex("xyz", []) ?? "", /Hexadecimal/);
    assert.equal(validate.passphrase("secret123"), undefined);
    assert.ok(validate.passphrase("short"));
    assert.ok(validate.passphrase("non-ascii é secret"));
    assert.ok(validate.ssid("x".repeat(33)));
    assert.equal(validate.address("10.0.0.0/8"), undefined);
    assert.equal(validate.address(""), undefined);
    assert.ok(validate.address("10.0.0.1, 10.0.0.2"));
    assert.equal(validate.spi("0x00001001"), undefined);
    assert.ok(validate.spi("0x1; rm -rf"));
  });
});
