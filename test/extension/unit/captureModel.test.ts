import * as assert from "node:assert/strict";
import {
  FILE_ARGS,
  fileCheck,
  fileParams,
  captureFileName,
  captureLimits,
  epochNs,
  formatDateTime,
  isFrameRanges,
  nsToSeconds,
  parseCaptureTime,
  parseDateTime,
  parseDuration,
} from "../../../src/captureModel";

const S = 1_000_000_000n;

suite("live capture and editing helpers", () => {
  test("Keep Packets' packet ranges, without catastrophic backtracking", () => {
    for (const ok of ["1", "1-100", "300-", "1-100, 250, 300-", " 1-100 250\t300- ", "1,,2"]) {
      assert.ok(isFrameRanges(ok), ok);
    }
    for (const bad of ["", " , ", "a", "1-2-3", "-5", "1 x", "1.5"]) {
      assert.ok(!isFrameRanges(bad), bad);
    }
    // The old regular expression took seconds here (doubling per range).
    const start = Date.now();
    assert.ok(!isFrameRanges("1  ".repeat(5000) + "x"));
    assert.ok(Date.now() - start < 1000);
  });

  test("stop conditions from the settings", () => {
    assert.deepEqual(captureLimits(0, 0, 0), {});
    assert.deepEqual(captureLimits(1000.4, 60, 1.5), {
      packets: 1000,
      seconds: 60,
      bytes: 1_500_000,
    });
    assert.deepEqual(captureLimits(-5, "10", null), {}, "nonsense is no limit");
  });

  test("capture file names", () => {
    const date = new Date(2026, 8, 27, 13, 4, 5);
    assert.equal(captureFileName(["eth0"], date), "capture_eth0_2026-09-27_13-04-05.pcapng");
    assert.equal(
      captureFileName(["Wi-Fi", "Ethernet 2"], date),
      "capture_Wi-Fi+Ethernet_2_2026-09-27_13-04-05.pcapng",
    );
    assert.equal(
      captureFileName(["\\Device\\NPF_{A1B2}"], date),
      "capture__Device_NPF__A1B2__2026-09-27_13-04-05.pcapng",
      "nothing a file system refuses",
    );
    assert.match(captureFileName(["a", "b", "c", "d"], date), /^capture_a\+b\+c\+more_/);
  });

  test("durations", () => {
    assert.equal(parseDuration("-3600"), -3600n * S);
    assert.equal(parseDuration("0.5"), S / 2n);
    assert.equal(parseDuration("+.25"), S / 4n);
    assert.equal(parseDuration("0.000000001"), 1n);
    assert.equal(parseDuration("1:30:00"), 5400n * S);
    assert.equal(parseDuration("-0:00:01.5"), -(S + S / 2n));
    assert.equal(parseDuration("2:30"), 150n * S, "minutes:seconds");
    assert.equal(parseDuration("1h 30m"), 5400n * S);
    assert.equal(parseDuration("-2d"), -172_800n * S);
    assert.equal(parseDuration("1.5s 250ms"), S + S / 2n + S / 4n);
    for (const bad of ["", "abc", "1x", "1h foo", "1::2", "--1", "1.2.3"]) {
      assert.equal(parseDuration(bad), undefined, bad);
    }
  });

  test("seconds for editcap", () => {
    assert.equal(nsToSeconds(-3600n * S - S / 4n), "-3600.25");
    assert.equal(nsToSeconds(1n), "0.000000001");
    assert.equal(nsToSeconds(0n), "0");
    assert.equal(nsToSeconds(90n * S), "90");
    assert.equal(epochNs(1700000000.000123), 1700000000_000123000n);
  });

  test("date-times", () => {
    assert.equal(parseDateTime("2023-11-14T22:13:20Z"), 1700000000n * S);
    assert.equal(parseDateTime("2023-11-14 22:13:20.5Z"), 1700000000n * S + S / 2n);
    assert.equal(parseDateTime("2023-11-15 00:13:20+02:00"), 1700000000n * S);
    assert.equal(parseDateTime("2023-11-14 17:13:20 -0500"), 1700000000n * S);
    const local = parseDateTime("2023-11-14 22:13:20.123456");
    assert.ok(local !== undefined);
    assert.equal(formatDateTime(local), "2023-11-14 22:13:20.123456", "local time round trip");
    for (const bad of ["2023-02-30 00:00:00", "2023-11-14", "22:13:20", "2023-11-14 25:00:00"]) {
      assert.equal(parseDateTime(bad), undefined, bad);
    }
  });

  test("times for keeping a range: absolute, or from the first packet", () => {
    const first = 1700000000n * S;
    assert.equal(parseCaptureTime("+10s", first), first + 10n * S);
    assert.equal(parseCaptureTime("90", first), first + 90n * S);
    assert.equal(parseCaptureTime("2023-11-14T22:13:21Z", first), first + S);
    assert.equal(parseCaptureTime("soon", first), undefined);
  });

  test("Capture to Files: the form's values as capture_to_files' options", () => {
    assert.deepEqual(
      FILE_ARGS.map((a) => a.call),
      [
        "--switchMegabytes",
        "--switchSeconds",
        "--switchPackets",
        "--ring",
        "--stopAfter",
        "--stopPackets",
        "--stopSeconds",
        "--format",
      ],
    );
    assert.deepEqual(
      fileParams({
        "--switchMegabytes": "1.5",
        "--switchPackets": "",
        "--ring": "5",
        "--stopSeconds": "3600",
        "--format": "pcap",
      }),
      {
        format: "pcap",
        files: { switchBytes: 1_500_000, ring: 5 },
        limits: { seconds: 3600 },
      },
    );
    assert.deepEqual(fileParams({}), { format: "pcapng", files: {}, limits: {} });
    assert.match(fileCheck({ "--ring": "5" }) ?? "", /needs a new file/);
    assert.equal(fileCheck({ "--ring": "5", "--switchSeconds": "60" }), undefined);
    assert.equal(fileCheck({}), undefined);
  });
});
