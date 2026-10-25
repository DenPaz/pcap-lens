import * as assert from "assert";
import { Scan, scanFilter, scanNote, scanSection, scanSentence } from "../../../src/aiScans";

const OFFICE: Scan = {
  kind: "port scan",
  protocol: "tcp",
  client: "10.0.0.66",
  server: "10.0.0.80",
  ports: [22, 23, 445, 3389, 5900],
  targets: 5,
  packets: 10,
  reset: 5,
};

suite("aiScans", () => {
  test("a scan as a sentence: targets, packets, and the resets it drew", () => {
    assert.equal(
      scanSentence(OFFICE),
      "Port scan: 10.0.0.66 reached 5 TCP ports of 10.0.0.80 (22, 23, 445, 3389, 5900), 10 packets," +
        " a few per connection; 5 of the 5 ports answered with a TCP reset (closed or refused:" +
        " those resets are the scan's answers).",
    );
    assert.match(
      scanSentence({ ...OFFICE, reset: 0 }, "only in the after capture"),
      /^Port scan, only in the after capture: .*; none answered with a TCP reset\.$/,
    );
    // UDP (no resets counted) and a sweep whose server list was cut by the backend.
    const servers = Array.from({ length: 50 }, (_, i) => `10.0.1.${i + 1}`);
    assert.equal(
      scanSentence({
        kind: "host sweep",
        protocol: "udp",
        client: "10.0.0.9",
        port: 161,
        servers,
        targets: 70,
        packets: 140,
      }),
      "Host sweep: 10.0.0.9 reached UDP port 161 on 70 servers (10.0.1.1, 10.0.1.2, 10.0.1.3," +
        " 10.0.1.4, 10.0.1.5, 10.0.1.6, 10.0.1.7, 10.0.1.8, …), 140 packets, a few per connection.",
    );
    // An older profile without `targets` counts the list.
    assert.match(scanSentence({ ...OFFICE, targets: undefined }), /reached 5 TCP ports/);
  });

  test("filters: the client's packets to the scanned ports, none for a partial list", () => {
    assert.equal(
      scanFilter(OFFICE),
      "ip.src == 10.0.0.66 && ip.dst == 10.0.0.80 && tcp.dstport in {22,23,445,3389,5900}",
    );
    assert.equal(
      scanFilter({ ...OFFICE, targets: 400 }),
      "ip.src == 10.0.0.66 && ip.dst == 10.0.0.80",
    );
  });

  test("the prompt section and the chat note", () => {
    assert.deepEqual(scanSection([]), []);
    const section = scanSection([{ scan: OFFICE }]);
    assert.equal(section[0], "## Scans tshark's numbers show");
    assert.match(section.join("\n"), /Resets on a scan's ports are its targets refusing/);
    assert.match(section.at(-2) ?? "", /^- Port scan: 10\.0\.0\.66/);

    assert.deepEqual(scanNote([]), { markdown: "", filters: [] });
    const note = scanNote([{ scan: OFFICE }, { scan: OFFICE, where: "in both captures" }]);
    assert.match(note.markdown, /^\*\*Found by tshark\*\*\n\n- Port scan: /);
    assert.match(note.markdown, /- Port scan, in both captures: /);
    assert.deepEqual(note.filters, [scanFilter(OFFICE)]); // (once)
    // Markdown in an address can't format the note.
    const odd = scanNote([{ scan: { ...OFFICE, client: "*a*", server: "b_c" } }]);
    assert.match(odd.markdown, /\\\*a\\\* reached 5 TCP ports of b\\_c/);
  });
});
