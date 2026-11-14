// @ts-check
/**
 * HTTP Exchange panel: one request and its response, each with its first
 * line, its headers and its body (decoded by tshark: de-chunked,
 * decompressed). A body is shown pretty-printed (JSON, XML, HTML, forms:
 * lib.prettyBody, coloured spans holding text), as text, as a hex dump or as
 * an image. Everything here came from the capture: text only goes in with
 * textContent, an image only as a data: URL in <img>.
 */
(function () {
  "use strict";

  const kit = /** @type {any} */ (window).PcapPanel;
  const h = kit.h;
  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;
  /** Characters drawn at most per body (the rest: Save or Show Packet Bytes). */
  const RENDER_BUDGET = 2_000_000;

  /**
   * @typedef {{frame: number, kind: "request"|"response", line: string,
   *   headers: [string, string][], body: string, bodySize: number,
   *   truncated: boolean, decoded: boolean}} Message
   */

  const state = {
    label: "",
    /** @type {Message | null} */ request: null,
    /** @type {Message | null} */ response: null,
    /** The view picked per side ("" until a body is shown: its best one). */
    view: { request: "", response: "" },
  };

  const app = /** @type {HTMLElement} */ (document.getElementById("app"));
  const title = h("h1", { class: "panel-title" }, ["HTTP Exchange"]);
  const status = h("div", { class: "status", role: "status" });
  const notice = h("div", { class: "notice error hidden", role: "alert" });
  const sides = h("div", { class: "http-sides" });
  app.append(title, status, notice, sides);

  window.addEventListener("message", (event) => {
    // VS Code posts to this frame with its own origin as the target; ignore other senders.
    if (event.origin !== window.origin) {
      return;
    }
    const msg = event.data;
    if (msg.type === "loading") {
      state.label = String(msg.label || "");
      status.textContent = `Reading ${state.label || "the exchange"}…`;
      notice.classList.add("hidden");
    } else if (msg.type === "show") {
      state.label = String(msg.label || "");
      state.request = msg.request;
      state.response = msg.response;
      state.view = { request: "", response: "" };
      render();
    } else if (msg.type === "error") {
      status.textContent = "";
      notice.textContent = String(msg.message);
      notice.classList.remove("hidden");
    }
  });

  function render() {
    notice.classList.add("hidden");
    title.textContent = state.label ? `HTTP Exchange: ${state.label}` : "HTTP Exchange";
    const ms = [state.request, state.response];
    status.textContent = state.response
      ? `Request in packet ${state.request?.frame}, response in packet ${state.response.frame}`
      : `Request in packet ${state.request?.frame ?? "?"} · no response in the capture`;
    sides.replaceChildren(
      side("request", ms[0], "Request"),
      side("response", ms[1], state.response ? "Response" : "No response"),
    );
  }

  /**
   * One message: heading with its packet, first line, headers, body.
   * @param {"request"|"response"} which @param {Message | null} m @param {string} heading
   */
  function side(which, m, heading) {
    const section = h("section", { class: "http-side", "aria-label": heading });
    const head = h("h2", {}, [heading]);
    section.append(head);
    if (!m) {
      section.append(
        h("p", { class: "empty" }, [
          which === "request"
            ? "The request couldn't be read."
            : "Nothing in the capture answers this request.",
        ]),
      );
      return section;
    }
    const go = h("button", { type: "button", class: "link" }, [`Packet ${m.frame}`]);
    go.addEventListener("click", () => vscode.postMessage({ type: "goto", frame: m.frame }));
    head.append(" ", go);
    section.append(h("pre", { class: "http-line" }, [m.line]));
    const table = h("table", { class: "stats http-headers" }, [
      h("thead", {}, [
        h("tr", {}, [h("th", { scope: "col" }, ["Header"]), h("th", { scope: "col" }, ["Value"])]),
      ]),
    ]);
    const body = h("tbody");
    for (const [name, value] of m.headers) {
      body.append(h("tr", {}, [h("td", {}, [name]), h("td", { class: "wrap" }, [value])]));
    }
    if (!m.headers.length) {
      body.append(h("tr", {}, [h("td", { colspan: "2", class: "empty" }, ["No headers"])]));
    }
    table.append(body);
    const copyHeaders = h("button", { type: "button", class: "secondary" }, ["Copy Headers"]);
    copyHeaders.addEventListener("click", () =>
      vscode.postMessage({
        type: "copy",
        text: [m.line, ...m.headers.map(([n, v]) => `${n}: ${v}`)].join("\n"),
      }),
    );
    section.append(table, h("div", { class: "toolbar" }, [kit.withIcon(copyHeaders, "copy")]));
    section.append(bodyView(which, m));
    return section;
  }

  /** The message's Content-Type header ("" without one). @param {Message} m */
  function contentType(m) {
    const header = m.headers.find(([n]) => n.toLowerCase() === "content-type");
    return header ? header[1] : "";
  }

  /**
   * A body: its views (Pretty when it has one, Text, Hex dump, Image), what
   * tshark decoded, and Copy, Save, Show Packet Bytes.
   * @param {"request"|"response"} which @param {Message} m
   */
  function bodyView(which, m) {
    const box = h("div", { class: "http-body" });
    const bytes = lib.hexToBytes(m.body);
    const type = contentType(m);
    const kind = lib.bodyKind(type, bytes);
    const heading = h("h3", {}, ["Body"]);
    box.append(heading);
    if (kind === "empty") {
      box.append(h("p", { class: "empty" }, ["No body"]));
      return box;
    }
    const text = kind === "image" || kind === "binary" ? "" : lib.decodeBody(bytes, type);
    const pretty = lib.prettyBody(kind, text);
    /** @type {[string, string][]} */
    const views = [];
    if (pretty) {
      views.push(["pretty", "Pretty"]);
    }
    if (kind === "image") {
      views.push(["image", "Image"]);
    } else if (kind !== "binary") {
      views.push(["text", "Text"]);
    }
    views.push(["hexdump", "Hex dump"]);
    const view = views.some(([v]) => v === state.view[which]) ? state.view[which] : views[0][0];
    const select = /** @type {HTMLSelectElement} */ (
      h("select", { "aria-label": `Show the ${which} body as` })
    );
    for (const [value, label] of views) {
      select.append(h("option", { value }, [label]));
    }
    select.value = view;
    select.addEventListener("change", () => {
      state.view[which] = select.value;
      box.replaceWith(bodyView(which, m));
    });
    const facts = [
      `${m.bodySize.toLocaleString()} bytes`,
      ...(type ? [type] : []),
      ...(m.decoded ? ["decoded by tshark (de-chunked, decompressed)"] : []),
      ...(m.truncated ? ["the first 16 MB shown"] : []),
    ];
    const copyBtn = kit.withIcon(
      h("button", { type: "button", class: "secondary" }, ["Copy"]),
      "copy",
    );
    const saveBtn = kit.withIcon(
      h("button", { type: "button", class: "secondary" }, ["Save…"]),
      "save",
    );
    const bytesBtn = kit.withIcon(
      h("button", { type: "button", class: "secondary", title: "Decode or view it another way" }, [
        "Show Packet Bytes",
      ]),
      "file-binary",
    );
    const shownText = () =>
      view === "pretty" && pretty
        ? pretty.map(([t]) => t).join("")
        : view === "hexdump"
          ? lib.bytesAs(bytes, "hexdump")
          : text;
    copyBtn.toggleAttribute("disabled", view === "image");
    copyBtn.addEventListener("click", () =>
      vscode.postMessage({ type: "copy", text: shownText() }),
    );
    saveBtn.addEventListener("click", () =>
      vscode.postMessage({ type: "save", which, base64: lib.bytesToBase64(bytes) }),
    );
    bytesBtn.addEventListener("click", () => vscode.postMessage({ type: "bytes", which }));
    box.append(
      h("div", { class: "toolbar" }, [
        h("label", {}, ["Show as ", select]),
        h("span", { class: "facts" }, [facts.join(" · ")]),
        h("span", { class: "spacer" }),
        copyBtn,
        saveBtn,
        bytesBtn,
      ]),
    );
    if (view === "image") {
      const mime = lib.imageMime(bytes);
      const img = /** @type {HTMLImageElement} */ (
        h("img", { class: "http-image", alt: `The ${which} body (${mime})` })
      );
      img.src = `data:${mime};base64,${lib.bytesToBase64(bytes)}`;
      box.append(img);
      return box;
    }
    const pre = h("pre", {
      class: "http-code",
      tabindex: "0",
      "aria-label": `The ${which} body`,
    });
    let budget = RENDER_BUDGET;
    let clipped = false;
    if (view === "pretty" && pretty) {
      for (const [t, cls] of pretty) {
        if (budget <= 0) {
          clipped = true;
          break;
        }
        const piece = t.length > budget ? t.slice(0, budget) : t;
        clipped ||= piece.length < t.length;
        budget -= piece.length;
        pre.append(cls ? h("span", { class: cls }, [piece]) : document.createTextNode(piece));
      }
    } else {
      const all = shownText();
      clipped = all.length > budget;
      pre.textContent = clipped ? all.slice(0, budget) : all;
    }
    box.append(pre);
    if (clipped) {
      box.append(
        h("p", { class: "empty" }, [
          `Only the first ${RENDER_BUDGET.toLocaleString()} characters are shown: save the body to get all of it.`,
        ]),
      );
    }
    return box;
  }

  vscode.postMessage({ type: "ready" });
})();
