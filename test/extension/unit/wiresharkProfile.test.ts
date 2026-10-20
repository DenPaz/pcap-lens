import * as assert from "node:assert/strict";
import {
  type ProfileContents,
  importChoices,
  importSettings,
  normalizeProfileName,
  profileItems,
} from "../../../src/wiresharkProfile";

const CONTENTS: ProfileContents = {
  name: "Mine",
  path: "/home/u/.config/wireshark/profiles/Mine",
  coloringRules: [
    {
      name: "Bad TCP",
      filter: "tcp.analysis.flags",
      foreground: "#000000",
      background: "#ff5f5f",
      enabled: true,
    },
    { name: "", filter: "http", foreground: "#000000", background: "#e4ffc7", enabled: false },
  ],
  filterButtons: [
    { label: "Web", filter: "http || tls", comment: "Web traffic", enabled: true },
    { label: "DNS", filter: "dns", comment: "", enabled: true },
    { label: "Off", filter: "arp", comment: "", enabled: false },
  ],
  savedFilters: [
    { name: "No ARP", filter: "not arp" },
    { name: "Web", filter: "http" },
  ],
  macros: [{ name: "web", text: "tcp.port == $1" }],
  columns: [
    { title: "No.", id: "number" },
    { title: "Source", id: "source" },
    { title: "TTL", field: "ip.ttl" },
    { title: "Info", id: "info" },
  ],
  preferences: 3,
  decodeAs: 1,
};

suite("Wireshark profiles", () => {
  test("normalizeProfileName: what tshark's -C takes, else the Default profile", () => {
    assert.equal(normalizeProfileName(" No Reassembly "), "No Reassembly");
    for (const bad of [undefined, 3, "", "a/b", "..", "Default", "x\ny"]) {
      assert.equal(normalizeProfileName(bad), "", String(bad));
    }
  });

  test("profileItems: the current one checked, where each comes from and what it has", () => {
    const items = profileItems(
      [
        { name: "Default", path: "/p", default: true, global: false, files: ["preferences"] },
        { name: "Mine", path: "/p/profiles/Mine", default: false, global: false, files: [] },
        {
          name: "Classic",
          path: "/g/profiles/Classic",
          default: false,
          global: true,
          files: ["colorfilters", "dfilter_macros"],
        },
      ],
      "Mine",
    );
    assert.deepEqual(
      items.map((i) => [i.label, i.description, i.detail, i.name]),
      [
        ["Default", "your personal configuration", "Has preferences", ""],
        ["$(check) Mine", "", "No configuration files of its own", "Mine"],
        ["Classic", "shipped with Wireshark", "Has coloring rules, filter macros", "Classic"],
      ],
    );
  });

  test("importChoices: only what the profile has, counted", () => {
    assert.deepEqual(
      importChoices(CONTENTS).map((c) => [c.kind, c.label]),
      [
        ["coloringRules", "2 coloring rules"],
        ["filterButtons", "2 filter buttons"],
        ["savedFilters", "2 saved display filters"],
        ["columns", "4 packet list columns"],
      ],
    );
    assert.match(importChoices(CONTENTS)[3].detail, /its 1 custom column added/);
    const empty = {
      ...CONTENTS,
      coloringRules: [],
      filterButtons: [],
      savedFilters: [],
      columns: [],
    };
    assert.deepEqual(importChoices(empty), []);
  });

  test("importSettings: rules replace, buttons and filters add, columns set the layout", () => {
    const current = {
      filterButtons: [{ label: "DNS", filter: "dns" }],
      savedFilters: [{ name: "Web", filter: "tcp.port == 80" }],
      columns: [{ field: "tcp.stream", title: "Stream" }],
    };
    assert.deepEqual(importSettings("coloringRules", CONTENTS, current).writes, [
      {
        key: "coloringRules",
        value: [
          {
            name: "Bad TCP",
            filter: "tcp.analysis.flags",
            foreground: "#000000",
            background: "#ff5f5f",
          },
          {
            name: "http",
            filter: "http",
            foreground: "#000000",
            background: "#e4ffc7",
            enabled: false,
          },
        ],
      },
    ]);
    const buttons = importSettings("filterButtons", CONTENTS, current);
    assert.equal(buttons.added, 1, "DNS is already there, Off is disabled");
    assert.deepEqual(buttons.writes[0].value, [
      { label: "DNS", filter: "dns" },
      { label: "Web", filter: "http || tls", comment: "Web traffic" },
    ]);
    const filters = importSettings("savedFilters", CONTENTS, current);
    assert.equal(filters.added, 1, "a name already used is skipped");
    assert.deepEqual(
      (filters.writes[0].value as { name: string }[]).map((f) => f.name),
      ["Web", "No ARP"],
    );
    const columns = importSettings("columns", CONTENTS, current);
    assert.deepEqual(columns.writes, [
      {
        key: "columns",
        value: [
          { field: "tcp.stream", title: "Stream" },
          { field: "ip.ttl", title: "TTL" },
        ],
      },
      {
        key: "columnLayout",
        value: {
          order: [
            "number",
            "source",
            "custom:ip.ttl",
            "info",
            "time",
            "destination",
            "protocol",
            "length",
            "custom:tcp.stream",
          ],
          hidden: ["time", "destination", "protocol", "length", "custom:tcp.stream"],
        },
      },
    ]);
  });
});
