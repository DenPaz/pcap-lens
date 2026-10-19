import * as assert from "node:assert/strict";
import {
  MAX_RECENT,
  forgetCapture,
  parseRecent,
  recentDescription,
  recentTooltip,
  relativeAge,
  rememberCapture,
  type RecentCapture,
} from "../../../src/recentCaptures";

const NOW = Date.UTC(2026, 9, 19, 12, 0, 0);

function capture(path: string, extra: Partial<RecentCapture> = {}): RecentCapture {
  return {
    path,
    frames: 1234,
    size: 2_100_000,
    startTime: null,
    endTime: null,
    fileType: null,
    linkType: null,
    openedAt: NOW,
    ...extra,
  };
}

suite("recent captures", () => {
  test("the latest open comes first, once per path, at most MAX_RECENT", () => {
    let list: RecentCapture[] = [];
    list = rememberCapture(list, capture("/a.pcap"));
    list = rememberCapture(list, capture("/b.pcap"));
    list = rememberCapture(list, capture("/a.pcap", { frames: 5 }));
    assert.deepEqual(
      list.map((e) => [e.path, e.frames]),
      [
        ["/a.pcap", 5],
        ["/b.pcap", 1234],
      ],
    );
    for (let i = 0; i < 30; i++) {
      list = rememberCapture(list, capture(`/c${i}.pcap`));
    }
    assert.equal(list.length, MAX_RECENT);
    assert.equal(list[0].path, "/c29.pcap");
    assert.deepEqual(
      forgetCapture(list, "/c29.pcap")
        .map((e) => e.path)
        .slice(0, 1),
      ["/c28.pcap"],
    );
  });

  test("the stored list is checked (it is user data)", () => {
    assert.deepEqual(parseRecent(undefined), []);
    assert.deepEqual(parseRecent({ path: "/a" }), []);
    const parsed = parseRecent([
      capture("/a.pcap", { fileType: "pcap", startTime: 1 }),
      { path: "/b.pcap" },
      "junk",
      { ...capture("/c.pcap"), linkType: 7 },
    ]);
    assert.deepEqual(
      parsed.map((e) => [e.path, e.fileType, e.startTime, e.linkType]),
      [
        ["/a.pcap", "pcap", 1, null],
        ["/c.pcap", null, null, null],
      ],
    );
  });

  test("ages, the description and the tooltip", () => {
    assert.equal(relativeAge(NOW - 10_000, NOW), "just now");
    assert.equal(relativeAge(NOW - 5 * 60_000, NOW), "5 min ago");
    assert.equal(relativeAge(NOW - 3 * 3_600_000, NOW), "3 h ago");
    assert.equal(relativeAge(NOW - 30 * 3_600_000, NOW), "yesterday");
    assert.equal(relativeAge(NOW - 4 * 86_400_000, NOW), "4 days ago");
    assert.equal(relativeAge(Date.UTC(2026, 0, 2), NOW), "2026-01-02");
    assert.equal(relativeAge(NOW + 60_000, NOW), "just now"); // (a clock that went back)

    const entry = capture("/data/trace.pcapng", {
      frames: 1,
      openedAt: NOW - 3 * 3_600_000,
      fileType: "pcapng",
      linkType: "ether",
      startTime: Date.UTC(2026, 9, 18, 8, 30, 0) / 1000,
      endTime: Date.UTC(2026, 9, 18, 8, 30, 0) / 1000 + 90,
    });
    assert.equal(recentDescription(entry, NOW), "1 packet · 2.1 MB · 3 h ago");
    assert.deepEqual(recentTooltip(entry, NOW), [
      "/data/trace.pcapng",
      "1 packet, 2.1 MB (pcapng, ether)",
      "From 2026-10-18 08:30:00 UTC, 90 s",
      "Opened 3 h ago",
    ]);
  });
});
