import * as assert from "node:assert/strict";
import { DEFAULT_REORDER, normalizeSequenceParams } from "../../../src/sequenceModel";

suite("sequenceModel", () => {
  test("normalizeSequenceParams keeps field names, a known wrap and a window", () => {
    assert.deepEqual(
      normalizeSequenceParams({
        key: ["gtp.teid", " x2.liid ", "gtp.teid", "bad name", 3],
        seq: "gtp.seq_number",
        wrap: 65536,
        reorder: 50,
      }),
      { key: ["gtp.teid", "x2.liid"], seq: "gtp.seq_number", wrap: 65536, reorder: 50 },
    );
    // A comma-separated key, at most four fields.
    assert.deepEqual(normalizeSequenceParams({ key: "a, b,c,d,e", seq: "n" }).key, [
      "a",
      "b",
      "c",
      "d",
    ]);
    // Anything else: the defaults.
    assert.deepEqual(normalizeSequenceParams({ seq: "a b", wrap: 1000, reorder: 0 }), {
      key: [],
      seq: "",
      wrap: 0,
      reorder: DEFAULT_REORDER,
    });
    assert.deepEqual(normalizeSequenceParams(undefined), {
      key: [],
      seq: "",
      wrap: 0,
      reorder: DEFAULT_REORDER,
    });
  });
});
