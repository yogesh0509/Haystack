// Builds haystack.pptx, the project overview deck. Re-run after any edit:
//
//   cd deck && npm install && node build.js
//
// Every number on a slide is taken from the repository and the source is named in that slide's
// speaker notes. The one image, assets/demo-lab.png, is a real capture of the demo's Lab tab
// (regtest chain, one plain and one padded sync at padding 10).

const path = require("path");
const fs = require("fs");
const pptxgen = require("pptxgenjs");

const OUT = path.join(__dirname, "haystack.pptx");
const REPO_URL = "github.com/yogesh0509/Haystack";

// Colours are the demo page's light theme (demo/index.html, :root). The repo has no logo or brand
// guide, so the page's palette and font stack are the project's visual identity.
const THEME = {
  name: "Haystack",
  headFontFace: "Segoe UI", // demo/index.html: system-ui, -apple-system, "Segoe UI", sans-serif
  bodyFontFace: "Segoe UI",
  colors: {
    dk1: "1D2330", // --ink
    lt1: "FFFFFF", // --card
    dk2: "5D6677", // --muted
    lt2: "F6F7F9", // --bg
    accent1: "2F6FDE", // --accent
    accent2: "C2412D", // --bad: exposed
    accent3: "1F8A4C", // --good: hidden
    accent4: "9A6A00", // --warn: partly hidden
    accent5: "DDE1E8", // --line
    accent6: "EEF1F6", // --chip
    hlink: "2F6FDE",
    folHlink: "5D6677",
  },
};
const MONO = "Consolas"; // in demo/index.html's --mono stack

// Layout grid, in inches, defined once. 16:9 widescreen is 13.333 × 7.5.
const L = { W: 13.333, H: 7.5, MX: 0.6, TITLE_Y: 0.42, TITLE_H: 0.85, TOP: 1.5 };
L.CW = L.W - 2 * L.MX; // content width
L.RIGHT = L.W - L.MX; // right content edge
const FS = { wordmark: 72, title: 34, lead: 22, body: 18, label: 16, small: 14, caption: 12, stat: 54 };

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.title = "Haystack: private Electrum sync";
pres.subject = "Project overview";
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
const C = pres.SchemeColor;

// ---- Layouts ---------------------------------------------------------------------------------

pres.defineSlideMaster({
  title: "DARK",
  background: { color: C.text1 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.9, y: 2.0, w: 7.2, h: 1.3, fontSize: FS.wordmark,
      bold: true, color: C.background1, align: "left", valign: "bottom", margin: 0 }, text: "" } },
    { placeholder: { options: { name: "body", type: "body", x: 0.9, y: 3.4, w: 7.2, h: 0.7, fontSize: 32,
      color: C.accent5, valign: "top", margin: 0 }, text: "" } },
  ],
});

pres.defineSlideMaster({
  title: "CONTENT",
  background: { color: C.background2 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: L.MX, y: L.TITLE_Y, w: L.CW, h: L.TITLE_H,
      fontSize: FS.title, bold: true, color: C.text1, align: "left", valign: "middle", margin: 0 }, text: "" } },
    { text: { text: "Haystack · private Electrum sync", options: { x: L.MX, y: 7.0, w: 6, h: 0.3,
      fontSize: FS.caption, color: C.text2, margin: 0 } } },
  ],
  slideNumber: { x: L.RIGHT - 1.0, y: 7.0, w: 1.0, h: 0.3, fontSize: FS.caption, color: C.text2, align: "right", margin: 0 },
});

// ---- Drawing vocabulary ----------------------------------------------------------------------
// One shape per concept, reused on every slide: a real address is a solid blue square, a decoy an
// outlined square (fill and outline differ, not only colour); a component on the user's device is
// a white card, the Electrum server a dark box, a measurement tool a dashed card.

function text(slide, str, o) {
  slide.addText(str, Object.assign({ isTextBox: true, margin: 0, fontSize: FS.body, color: C.text1, valign: "top" }, o));
}

function square(slide, x, y, s, kind, dark) {
  const real = kind === "real";
  slide.addShape(pres.ShapeType.rect, {
    x, y, w: s, h: s,
    fill: { color: real ? C.accent1 : dark ? C.text1 : C.background1 },
    line: { color: real ? C.accent1 : C.text2, width: 0.75 },
  });
}

// cols × rows squares; `isReal(i)` picks the real ones by index in reading order.
function grid(slide, x, y, cols, rows, s, pitch, isReal, dark) {
  for (let i = 0; i < cols * rows; i++) {
    square(slide, x + (i % cols) * pitch, y + Math.floor(i / cols) * pitch, s, isReal(i) ? "real" : "decoy", dark);
  }
}

function card(slide, x, y, w, h, o = {}) {
  const line = { color: o.line || C.accent5, width: o.lineWidth || 1 };
  if (o.dash) line.dashType = "dash";
  slide.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.1, fill: { color: o.fill || C.background1 }, line, objectName: o.name });
}

// A labelled component box. kind: "device" (white card), "server" (dark box), "lab" (dashed card).
function component(slide, x, y, w, h, title, sub, kind = "device", o = {}) {
  const server = kind === "server";
  const line = { color: server ? C.text1 : kind === "lab" ? C.text2 : C.accent5, width: kind === "lab" ? 1.25 : 1 };
  if (kind === "lab") line.dashType = "dash";
  const runs = [{ text: title, options: { bold: true, fontSize: o.titleSize || FS.label, color: server ? C.background1 : C.text1,
    fontFace: o.monoTitle ? MONO : undefined, breakLine: !!sub } }];
  if (sub) runs.push({ text: sub, options: { fontSize: o.subSize || FS.small, color: server ? C.accent5 : C.text2 } });
  slide.addText(runs, {
    shape: pres.ShapeType.roundRect, rectRadius: 0.1, x, y, w, h,
    fill: { color: server ? C.text1 : C.background1 }, line,
    align: o.align || "center", valign: o.valign || "middle", margin: o.margin ?? 6, objectName: o.name || title,
  });
}

function arrow(slide, x1, y1, x2, y2, o = {}) {
  const line = { color: o.color || C.text2, width: o.width || 1.75, endArrowType: "triangle" };
  if (o.both) line.beginArrowType = "triangle";
  if (o.dash) line.dashType = "dash";
  slide.addShape(pres.ShapeType.line, {
    x: Math.min(x1, x2), y: Math.min(y1, y2), w: Math.abs(x2 - x1), h: Math.abs(y2 - y1),
    flipH: x2 < x1, flipV: y2 < y1, line,
  });
}

function badge(slide, x, y, d, label, color) {
  slide.addText(label, { shape: pres.ShapeType.ellipse, x, y, w: d, h: d, fill: { color }, line: { color },
    fontSize: FS.label, bold: true, color: C.background1, align: "center", valign: "middle", margin: 0 });
}

function content(title, section) {
  const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: section });
  s.addText(title, { placeholder: "title" });
  return s;
}

// The padding-10 field used on the title and closing slides: one real address in every ten.
const REAL_COL = [3, 7, 0, 5, 9, 2, 6, 1, 8, 4];
function field(slide, x, y) {
  grid(slide, x, y, 10, 10, 0.25, 0.35, (i) => i % 10 === REAL_COL[Math.floor(i / 10)], true);
  text(slide, "Padding 10: one real address (solid) in every ten sent", {
    x, y: y + 3.6, w: 3.4, h: 0.6, fontSize: FS.small, color: C.accent5 });
}

// ---- 1. Title --------------------------------------------------------------------------------

pres.addSection({ title: "Opening" });
{
  const s = pres.addSlide({ masterName: "DARK", sectionTitle: "Opening" });
  s.addText("Haystack", { placeholder: "title" });
  s.addText("Private Electrum sync", { placeholder: "body" });
  text(s, "A light wallet's real addresses, hidden among decoys, and the hiding measured by attacking it.", {
    x: 0.9, y: 4.25, w: 6.6, h: 1.0, fontSize: FS.lead, color: C.accent5 });
  text(s, [
    { text: "Built for BOSS Battle · Cypherpunk track", options: { breakLine: true } },
    { text: REPO_URL, options: { color: C.background1 } },
  ], { x: 0.9, y: 6.1, w: 7.5, h: 0.75, fontSize: FS.small, color: C.accent5, paraSpaceAfter: 4 });
  field(s, 8.9, 1.55);
  s.addNotes(
    "Haystack is about one specific leak: what a light Bitcoin wallet tells the server it syncs with. " +
    "It hides the wallet's real addresses among decoy addresses, so the server can't tell which ones are the wallet's. " +
    "The second half of the project is just as important: an attacker, written in the same repository, that plays the server and measures how well the hiding works. " +
    "The grid on the right is the idea in one picture: at padding 10, one address in every ten sent is real.");
}

// ---- 2. The problem --------------------------------------------------------------------------

pres.addSection({ title: "The problem" });
{
  const s = content("One sync hands over the whole wallet", "The problem");
  // One row: the wallet sends its 100 scripthashes, in the order the honeypot received them
  // (receive 0–49, then change 0–49), to the server.
  const sq0 = 0.24, p0 = 0.31, bw = 9 * p0 + sq0, bh = 4 * p0 + sq0; // one block: 10 × 5 squares
  const by = 2.55, boxY = by + (bh - 1.2) / 2, mid = by + bh / 2;
  const wallW = 2.1, b1 = 3.55, b2 = b1 + bw + 0.45, srvW = 2.05, srvX = L.RIGHT - srvW;
  component(s, L.MX, boxY, wallW, 1.2, "Light wallet", "stock bdk_wallet scan");
  arrow(s, L.MX + wallW + 0.05, mid, b1 - 0.1, mid, { color: C.text1 });
  text(s, "Receive addresses 0–49", { x: b1, y: by - 0.45, w: bw, h: 0.4, fontSize: FS.label, bold: true });
  grid(s, b1, by, 10, 5, sq0, p0, () => true);
  text(s, "then change 0–49", { x: b2, y: by - 0.45, w: bw, h: 0.4, fontSize: FS.label, bold: true });
  grid(s, b2, by, 10, 5, sq0, p0, () => true);
  arrow(s, b2 + bw + 0.1, mid, srvX - 0.05, mid, { color: C.text1 });
  component(s, srvX, boxY, srvW, 1.2, "Electrum server", "logs every query", "server");
  text(s, "one connection, one burst", { x: b1, y: by + bh + 0.15, w: b2 + bw - b1, h: 0.35, fontSize: FS.label, color: C.text2, align: "center" });
  text(s, "Each square is one address the server was asked about, in arrival order. All 100 belong to one wallet, and the order labels which ones hold change.", {
    x: L.MX, y: 4.95, w: L.CW, h: 0.8, fontSize: FS.body, color: C.text2 });
  text(s, "Source: a stock bdk_wallet full scan, logged by the repo's honeypot server (docs/00-problem.md §4).", {
    x: L.MX, y: 6.4, w: L.CW, h: 0.35, fontSize: FS.caption, color: C.text2 });
  s.addNotes(
    "A light wallet doesn't know which of its addresses have been used, so on every sync it asks the server about all of them, including the unused ones it will hand out next. " +
    "Electrum servers receive a scripthash, a SHA-256 of the address's script, but that hash is public and unkeyed, so it identifies the address as well as the address itself does. " +
    "The repo's honeypot, a fake server that logs every query, received all 100 of a stock bdk_wallet scan's scripthashes together, on one connection. " +
    "The first 50 were receive addresses and the last 50 change addresses, so even the change is labelled by order. " +
    "The operator ends up with the wallet's full address set, balance, history, change, and the addresses it will be paid at next.");
}

// ---- 3. The gap ------------------------------------------------------------------------------

{
  const s = content("Today's fixes leave a gap", "The problem");
  const colW = 3.71, gap = 0.5, xs = [L.MX, L.MX + colW + gap, L.MX + 2 * (colW + gap)];
  const top = (x, title, line, tag, tagColor, dash) => {
    card(s, x, 1.6, colW, 2.45, { dash, line: dash ? C.accent1 : undefined, lineWidth: dash ? 1.5 : 1 });
    text(s, tag, { x: x + 0.3, y: 1.8, w: colW - 0.6, h: 0.35, fontSize: FS.small, bold: true, color: tagColor, charSpacing: 1 });
    text(s, title, { x: x + 0.3, y: 2.15, w: colW - 0.6, h: 0.8, fontSize: FS.lead, bold: true, color: dash ? C.accent1 : C.text1 });
    text(s, line, { x: x + 0.3, y: 3.05, w: colW - 0.6, h: 0.9, fontSize: FS.label, color: C.text2 });
  };
  top(xs[0], "Ask a public Electrum server", "Cheap and easy. The server learns every address.", "NO PRIVACY", C.accent2);
  top(xs[1], "Privacy without a node", "Privacy from the Electrum servers wallets already use.", "HAYSTACK'S TARGET", C.accent1, true);
  top(xs[2], "Run your own node", "Private, but needs a machine, hundreds of GB and uptime.", "EXPERTS ONLY", C.accent4);

  text(s, "Partial fixes", { x: L.MX, y: 4.3, w: 4, h: 0.4, fontSize: FS.label, bold: true, color: C.text2 });
  const note = (x, name, line) => {
    card(s, x, 4.75, colW, 1.6);
    text(s, [{ text: name, options: { bold: true, breakLine: true } }, { text: line, options: { color: C.text2, fontSize: FS.label } }],
      { x: x + 0.3, y: 4.92, w: colW - 0.6, h: 1.3, fontSize: FS.body, paraSpaceAfter: 2 });
  };
  note(xs[0], "Tor", "Hides your IP address, not which addresses you ask about.");
  note(xs[1], "Bloom filters (BIP37)", "Bitcoin's first try. Wallets under about 20 addresses leak almost all of them.");
  note(xs[2], "Compact block filters", "Far more private, but heavy on mobile bandwidth and slow.");
  s.addNotes(
    "Today the private option is running your own node, which needs a machine, hundreds of gigabytes and constant uptime, so almost no mobile user does it, while asking a public Electrum server gives no privacy at all. " +
    "Tor hides your IP address, but the server still receives the complete labelled set of addresses. " +
    "Bloom filters, BIP37, were Bitcoin's first attempt to hide the address list; Gervais and colleagues showed in 2014 that a wallet with fewer than about 20 addresses reveals almost all of them, and that a restart makes it worse. " +
    "Compact block filters, BIP157 and 158, are the honest protocol-level answer, but the bandwidth is punishing on mobile, sync is slow, and the server still learns which blocks you fetched. " +
    "Haystack targets the space between the two ends, privacy from the Electrum servers wallets already use (docs/00-problem.md, section 7; docs/05-prior-art.md).");
}

// ---- 4. Introduction -------------------------------------------------------------------------

pres.addSection({ title: "Haystack" });
{
  const s = content("Haystack in four ideas", "Haystack");
  const colW = 2.83, gap = 0.27, y0 = 1.6, h = 4.4;
  const xs = [0, 1, 2, 3].map((i) => L.MX + i * (colW + gap));
  for (const x of xs) card(s, x, y0, colW, h);
  const glyphY = y0 + 0.4, titleY = y0 + 2.0, bodyY = y0 + 2.6, inset = 0.3, tw = colW - 2 * inset;

  // Padding: one real square and nine decoys.
  grid(s, xs[0] + inset, glyphY + 0.2, 5, 2, 0.32, 0.43, (i) => i === 0);
  // Decoy: one decoy square, the same shape as a real one.
  square(s, xs[1] + inset, glyphY + 0.2, 0.75, "decoy");
  text(s, "same shape, no owner", { x: xs[1] + inset + 0.95, y: glyphY + 0.32, w: 1.3, h: 0.6, fontSize: FS.small, color: C.text2 });
  // Ledger: the real ledger format from the demo, one line per keychain.
  s.addText([
    { text: "external 0–80: 9", options: { breakLine: true } },
    { text: "internal 0–51: 9" },
  ], { shape: pres.ShapeType.rect, x: xs[2] + inset, y: glyphY + 0.15, w: tw, h: 0.95, fill: { color: C.accent6 },
    line: { color: C.accent5 }, fontFace: MONO, fontSize: FS.small, color: C.text1, margin: 8, valign: "middle" });
  // Score: the bits scale from 0 to the padding-10 ceiling.
  const sx = xs[3] + inset, sw = tw, sy = glyphY + 0.6;
  s.addShape(pres.ShapeType.line, { x: sx, y: sy, w: sw, h: 0, line: { color: C.text1, width: 2 } });
  for (const [f, label] of [[0, "0"], [1, "3.32"]]) {
    s.addShape(pres.ShapeType.line, { x: sx + f * sw, y: sy - 0.12, w: 0, h: 0.24, line: { color: C.text1, width: 2 } });
    text(s, label, { x: sx + f * sw - 0.5, y: sy + 0.18, w: 1.0, h: 0.35, fontSize: FS.small, align: "center", color: C.text2 });
  }
  text(s, "bits", { x: sx, y: sy - 0.55, w: sw, h: 0.35, fontSize: FS.small, align: "center", color: C.text2 });

  const concept = (x, title, body) => {
    text(s, title, { x: x + inset, y: titleY, w: tw, h: 0.5, fontSize: FS.lead, bold: true });
    text(s, body, { x: x + inset, y: bodyY, w: tw, h: 1.75, fontSize: FS.body, color: C.text2 });
  };
  concept(xs[0], "Padding", "Each real address is sent with padding − 1 decoys. The user sets it on a dial.");
  concept(xs[1], "Decoy", "An address of the same type that nobody owns, from a keyed hash.");
  concept(xs[2], "Ledger", "Freezes each address's decoy count. Decoys are never withdrawn.");
  concept(xs[3], "Score", "The repo's attacker guesses which are real. The result, in bits.");
  s.addNotes(
    "Haystack sends each real address among decoys to an unmodified Electrum server, keeps only the real answers, and measures the hiding with its own attacker; four ideas carry it. Padding is the dial: at padding 10, each real address goes out with 9 decoys. " +
    "A decoy is a made-up address of the same script type as the real one, built from a keyed hash of the wallet's public keys, so nobody holds a key for it. " +
    "The ledger records, per keychain and index range, how many decoys each address was given the first time it was queried; the example shown is the real ledger the demo wrote, 9 decoys for external 0 to 80 and internal 0 to 51. " +
    "The score is what the repo's attacker achieves when it tries to pick the real addresses out, reported in bits; the next slides explain each one.");
}

// ---- 5. The score ----------------------------------------------------------------------------

pres.addSection({ title: "How it holds up" });
{
  const s = content("Privacy is measured in bits", "How it holds up");
  const colW = 3.84, gap = 0.31;
  const steps = [
    "The attacker picks as many addresses as the wallet really has.",
    "Precision is the share of its picks that are real.",
    "Score = −log₂(precision), capped at random guessing.",
  ];
  steps.forEach((t, i) => {
    const x = L.MX + i * (colW + gap);
    card(s, x, 1.55, colW, 1.55);
    badge(s, x + 0.3, 1.8, 0.5, String(i + 1), C.text1);
    text(s, t, { x: x + 1.0, y: 1.75, w: colW - 1.25, h: 1.2, fontSize: FS.body });
  });

  // The scale, 0 to the padding-10 ceiling of 3.32 bits.
  const x0 = 1.3, x1 = 11.95, y = 4.55, bx = (b) => x0 + (b / 3.32) * (x1 - x0);
  s.addShape(pres.ShapeType.line, { x: x0, y, w: x1 - x0, h: 0, line: { color: C.text1, width: 2.5 } });
  for (const b of [0, 1, 2, 3]) {
    s.addShape(pres.ShapeType.line, { x: bx(b), y: y - 0.1, w: 0, h: 0.2, line: { color: C.text1, width: 1.5 } });
    text(s, String(b), { x: bx(b) - 0.3, y: y + 0.15, w: 0.6, h: 0.3, fontSize: FS.small, color: C.text2, align: "center" });
  }
  text(s, "bits", { x: x0 - 0.95, y: y - 0.17, w: 0.6, h: 0.35, fontSize: FS.small, color: C.text2, align: "right" });
  // Haystack's measured range, 2.6 to 2.7 bits.
  s.addShape(pres.ShapeType.rect, { x: bx(2.6), y: y - 0.16, w: bx(2.7) - bx(2.6), h: 0.32, fill: { color: C.accent1 }, line: { color: C.accent1 } });
  const dot = (b, color) => s.addShape(pres.ShapeType.ellipse, { x: bx(b) - 0.16, y: y - 0.16, w: 0.32, h: 0.32, fill: { color }, line: { color: C.background2, width: 1.5 } });
  dot(0, C.accent2);
  dot(3.32, C.accent3);

  text(s, [{ text: "Plain Electrum: 0.00", options: { bold: true, color: C.accent2, breakLine: true } },
    { text: "every pick right: −log₂(1) = 0", options: { fontSize: FS.label, color: C.text2 } }],
  { x: x0 - 0.3, y: y + 0.55, w: 4.2, h: 0.85, fontSize: FS.body });
  text(s, [{ text: "Ceiling at padding 10: 3.32", options: { bold: true, color: C.accent3, breakLine: true } },
    { text: "10% right, as random: −log₂(0.1) = 3.32", options: { fontSize: FS.label, color: C.text2 } }],
  { x: x1 - 4.6, y: y + 0.55, w: 4.9, h: 0.85, fontSize: FS.body, align: "right" });
  text(s, [{ text: "Haystack at padding 10: about 2.6–2.7", options: { bold: true, color: C.accent1, breakLine: true } },
    { text: "structural attacker, mean of 13 test wallets", options: { fontSize: FS.label, color: C.text2 } }],
  { x: bx(2.65) - 2.45, y: y - 1.15, w: 4.9, h: 0.85, fontSize: FS.body, align: "center" });
  text(s, "A second score covers only addresses with coin history, so unused addresses can't hide exposed funds.", {
    x: L.MX, y: 6.2, w: L.CW, h: 0.45, fontSize: FS.label, color: C.text2 });
  s.addNotes(
    "The score answers one question: if the attacker names as many addresses as the wallet really has, how many of its picks are right? " +
    "Plain Electrum sends only real addresses, so every pick is right, precision is 100 percent, and minus log base 2 of 1 is 0 bits. " +
    "At padding 10, a random pick of 100 addresses out of 1,000 is right 10 percent of the time, and minus log base 2 of 0.1 is 3.32 bits, the most that setting can give. " +
    "Against the strongest attacker in the repo, which learns from 12 other wallets' syncs, Haystack scores about 2.6 to 2.7 bits averaged over 13 test wallets (README, 'What is finished'). " +
    "A second number, the same precision among addresses with coin history only, is always printed beside it, because the many unused addresses could otherwise hide exposed funds (docs/03-metric.md).");
}

// ---- 6. Why decoys never change --------------------------------------------------------------

{
  const s = content("Redrawn decoys are undone in three syncs", "How it holds up");
  text(s, "A 100-address wallet sends 900 decoys per sync. Each cell is the attacker's score after that sync, in bits.", {
    x: L.MX, y: 1.4, w: L.CW, h: 0.45, fontSize: FS.body, color: C.text2 });
  // Output of `python3 -m attack strategies` (docs/00-problem.md §6).
  const rows = [
    ["Fresh", "redrawn every sync", [3.32, 0.12, 0.0, 0.0, 0.0, 0.0]],
    ["Rotated", "redrawn every 3 syncs", [3.32, 3.32, 3.32, 0.08, 0.08, 0.08]],
    ["Fixed", "the same every sync", [3.32, 3.32, 3.32, 3.32, 3.32, 3.32]],
  ];
  const lx = L.MX, lw = 3.3, cx0 = 4.05, cw = 1.36, cg = 0.1, rh = 0.85, ry0 = 2.4, rg = 0.1;
  for (let c = 0; c < 6; c++) {
    text(s, `sync ${c + 1}`, { x: cx0 + c * (cw + cg), y: 1.98, w: cw, h: 0.35, fontSize: FS.label, color: C.text2, align: "center" });
  }
  rows.forEach(([name, sub, vals], r) => {
    const y = ry0 + r * (rh + rg);
    text(s, [{ text: name, options: { bold: true, breakLine: true } }, { text: sub, options: { fontSize: FS.label, color: C.text2 } }],
      { x: lx, y: y + 0.08, w: lw, h: rh - 0.1, fontSize: FS.body, valign: "middle" });
    if (name === "Fixed") {
      s.addText("Haystack", { shape: pres.ShapeType.roundRect, rectRadius: 0.15, x: lx + 0.95, y: y + 0.12, w: 1.15, h: 0.34,
        fill: { color: C.accent1 }, line: { color: C.accent1 }, fontSize: FS.small, bold: true, color: C.background1, align: "center", valign: "middle", margin: 0 });
    }
    vals.forEach((v, c) => {
      const hidden = v > 3;
      s.addText(v.toFixed(2), {
        shape: pres.ShapeType.rect, x: cx0 + c * (cw + cg), y, w: cw, h: rh,
        fill: { color: hidden ? C.accent3 : C.accent2, transparency: 86 }, line: { color: hidden ? C.accent3 : C.accent2, width: 0.75 },
        fontSize: FS.lead, bold: true, color: hidden ? C.accent3 : C.accent2, align: "center", valign: "middle", margin: 0,
      });
    });
  });
  text(s, "Real addresses appear in every sync and a redrawn decoy rarely does twice, so comparing syncs leaves only the wallet.", {
    x: L.MX, y: 5.4, w: L.CW, h: 0.8, fontSize: FS.body });
  text(s, "Output of python3 -m attack strategies (docs/00-problem.md §6), checked by tests/test_regression.py.", {
    x: L.MX, y: 6.4, w: L.CW, h: 0.35, fontSize: FS.caption, color: C.text2 });
  s.addNotes(
    "This is the most important result in the repo, and it rules out the obvious design. " +
    "If decoys are redrawn every sync, the server can intersect what two or three syncs asked for: the real addresses are in all of them, a fresh decoy almost never is. " +
    "After sync 2 only 9 decoys survive next to the 100 real addresses, which is 0.12 bits; after sync 3 none do. " +
    "Rotating decoys every three syncs only delays the same collapse to the first sync of the second epoch. " +
    "Keeping the same decoys forever leaves nothing to remove, which is the rule Haystack follows; the table is the real output of python3 -m attack strategies.");
}

// ---- 7. Architecture -------------------------------------------------------------------------

pres.addSection({ title: "Inside the repo" });
{
  const s = content("Four Rust crates and a Python attacker", "Inside the repo");
  const head = (x, w, t) => text(s, t, { x, y: 1.45, w, h: 0.4, fontSize: FS.label, bold: true, color: C.text2 });
  head(L.MX, 6.0, "On the device (trusted)");
  head(9.55, 3.2, "Measurement, run locally");

  component(s, L.MX, 1.95, 6.0, 0.9, "demo/", "the wallet page: dial, balance, score", "device", { monoTitle: true });
  component(s, L.MX, 3.25, 6.0, 0.75, "bdk_wallet (upstream)", "descriptors, keychains, stored transactions");
  arrow(s, 3.6, 2.9, 3.6, 3.2, { color: C.text1 });
  // haystack-electrum with its modules, one chip per source file.
  card(s, L.MX, 4.35, 6.0, 2.35);
  text(s, [{ text: "haystack-electrum/", options: { fontFace: MONO, bold: true } }, { text: "  the padded sync client", options: { color: C.text2, fontSize: FS.small } }],
    { x: L.MX + 0.25, y: 4.45, w: 5.6, h: 0.4, fontSize: FS.label });
  ["client", "planner", "decoy", "chain", "ledger", "cache_file", "session", "schedule", "key"].forEach((m, i) => {
    s.addText(m + ".rs", { shape: pres.ShapeType.roundRect, rectRadius: 0.05, x: L.MX + 0.25 + (i % 3) * 1.85, y: 4.95 + Math.floor(i / 3) * 0.55,
      w: 1.7, h: 0.42, fill: { color: C.accent6 }, line: { color: C.accent5 }, fontFace: MONO, fontSize: FS.small, color: C.text1,
      align: "center", valign: "middle", margin: 0 });
  });
  arrow(s, 3.6, 4.05, 3.6, 4.3, { color: C.text1, both: true });

  component(s, 7.0, 4.35, 2.2, 1.6, "Electrum server", "across the network, unmodified", "server");
  arrow(s, 6.65, 5.15, 6.95, 5.15, { color: C.text1, both: true });

  const lw = L.RIGHT - 9.55, lh = 1.35;
  component(s, 9.55, 1.95, lw, lh, "attack/  (Python)", "A1 compares syncs, A2 learns shape; prints bits", "lab", { monoTitle: true });
  component(s, 9.55, 3.65, lw, lh, "regtest/", "local chain, correctness tests, training sessions", "lab", { monoTitle: true });
  component(s, 9.55, 5.35, lw, lh, "capture/  scripts/", "stock-wallet baseline, honeypot server", "lab", { monoTitle: true });
  arrow(s, 6.65, 2.4, 9.5, 2.4, { color: C.text1, both: true });
  text(s, "session log in, score out", { x: 6.7, y: 1.98, w: 2.8, h: 0.35, fontSize: FS.small, color: C.text2, align: "center" });
  arrow(s, 9.55 + lw / 2, 3.6, 9.55 + lw / 2, 3.35, { color: C.text1 });
  s.addNotes(
    "The repo is a Cargo workspace of four crates plus a Python package. " +
    "haystack-electrum is the product: the padded client, with one file per job, from the planner that decides which positions to query to the ledger, the saved cache, the session log and the sync timer. " +
    "demo is a web wallet built from bdk_wallet's own Electrum example with only the five allowed changes; after every sync it runs the attacker on the session log and shows the score. " +
    "attack is the Python attacker: A1 compares syncs, A2 is a classifier trained on other wallets' sessions, which regtest generates on a local Bitcoin chain alongside the correctness tests. " +
    "capture and scripts record what an unmodified wallet sends and include the honeypot server, the baseline every score is calibrated against.");
}

// ---- 8. Product glimpse ----------------------------------------------------------------------

{
  const s = content("The demo: plain and Haystack side by side", "Inside the repo");
  const ih = 5.0, iw = ih * (2296 / 2122);
  s.addImage({ path: path.join(__dirname, "assets", "demo-lab.png"), x: L.MX, y: 1.45, w: iw, h: ih,
    altText: "The demo's Lab tab after one sync each. Plain Electrum: 133 addresses sent, 38.8 KiB, 0.00 bits from both attackers. Haystack at padding 10: 1,330 addresses sent, 260.4 KiB, 3.32 bits from the attacker that compares syncs and 2.46 bits from the trained attacker. Both copies show the same balance and 8 transactions, and both attackers find all 8 addresses with coin history." });
  text(s, "Real capture: one sync per copy, regtest chain (worthless coins).", {
    x: L.MX, y: 1.45 + ih + 0.1, w: iw, h: 0.3, fontSize: FS.caption, color: C.text2 });
  const cx = L.MX + iw + 0.45, cw = L.RIGHT - cx;
  const call = (i, y, head, body, color) => {
    badge(s, cx, y, 0.5, String(i), color);
    text(s, head, { x: cx + 0.7, y: y - 0.02, w: cw - 0.7, h: 0.45, fontSize: FS.body, bold: true });
    text(s, body, { x: cx + 0.7, y: y + 0.45, w: cw - 0.7, h: 1.05, fontSize: FS.label, color: C.text2 });
  };
  call(1, 1.6, "Same balance, same 8 transactions", "Padding changes what the server sees, not what the wallet shows.", C.text1);
  call(2, 3.25, "0.00 bits against 3.32 and 2.46", "Plain is fully exposed. Haystack is hidden from the comparing attacker and partly hidden from the trained one.", C.accent1);
  call(3, 4.9, "8 of 8 funded addresses found", "This restored wallet's addresses with coin history stay exposed: the main known limit.", C.accent2);
  s.addNotes(
    "This is the demo wallet's Lab tab, captured for this deck after one sync of each copy on a local regtest chain. " +
    "Both copies show the same balance and the same 8 transactions, which is the correctness claim made visible. " +
    "Plain Electrum sent 133 addresses and both attackers read 0.00 bits; Haystack sent 1,330 and read 3.32 bits from the attacker that compares syncs and 2.46 from the attacker trained on other wallets. " +
    "The data line reads 6.7 times the plain sync because this is a first sync; once the cache is warm, a padded sync costs about 8.4 times a plain one (docs/07-walkthrough.md, case 10). " +
    "Both copies also find 8 of 8 addresses with coin history: made-up decoys never have history, so a restored wallet's funded addresses stand out; that is Haystack's main known limit.");
}

// ---- 9. Demo, wallet tab ---------------------------------------------------------------------

// A named control on the demo page, shown as a label (not a drawing of the page).
function chip(slide, x, y, w, label, on) {
  slide.addText(label, { shape: pres.ShapeType.roundRect, rectRadius: 0.08, x, y, w, h: 0.42,
    fill: { color: on ? C.accent1 : C.accent6 }, line: { color: on ? C.accent1 : C.accent5 },
    fontSize: FS.label, bold: true, color: on ? C.background1 : C.text1, align: "center", valign: "middle", margin: 0 });
}
const halfW = (L.CW - 0.3) / 2, halfX = [L.MX, L.MX + halfW + 0.3];

{
  const s = content("Wallet tab: automatic sync and the dial", "Inside the repo");
  for (const x of halfX) card(s, x, 1.55, halfW, 5.15);
  const ix = halfX[0] + 0.35, iw = halfW - 0.7;
  text(s, "Automatic sync", { x: ix, y: 1.8, w: iw, h: 0.5, fontSize: FS.lead, bold: true });
  [
    "Fires at random times: every 2 minutes on average in the demo, 30 in the product.",
    "Runs a full scan through Haystack: every address with its decoys, only real answers kept.",
    "The attacker then scores the sync, and the page shows what it learned.",
  ].forEach((t, i) => {
    const y = 2.5 + i * 1.05;
    badge(s, ix, y, 0.45, String(i + 1), C.text1);
    text(s, t, { x: ix + 0.65, y: y - 0.05, w: iw - 0.65, h: 0.95, fontSize: FS.body });
  });
  text(s, "It never fires because you opened the app or got paid. Sync now is there too, but the server sees its timing.", {
    x: ix, y: 5.65, w: iw, h: 0.85, fontSize: FS.label, color: C.text2 });

  const jx = halfX[1] + 0.35, jw = halfW - 0.7;
  text(s, "Privacy dial", { x: jx, y: 1.8, w: jw, h: 0.5, fontSize: FS.lead, bold: true });
  text(s, "Padding", { x: jx, y: 2.45, w: jw, h: 0.4, fontSize: FS.label, bold: true, color: C.text2 });
  [2, 5, 10, 20].forEach((v, i) => chip(s, jx + i * 1.0, 2.9, 0.85, String(v), v === 10));
  text(s, "Chain decoys (regtest only)", { x: jx, y: 3.5, w: jw, h: 0.4, fontSize: FS.label, bold: true, color: C.text2 });
  ["0%", "10%", "30%"].forEach((v, i) => chip(s, jx + i * 1.0, 3.95, 0.85, v, i === 0));
  text(s, [
    { text: "Apply asks to confirm; the next sync uses the new setting.", options: { breakLine: true } },
    { text: "Addresses the server has seen keep their decoys. The page shows each setting's cost per sync and per day." },
  ], { x: jx, y: 4.6, w: jw, h: 1.9, fontSize: FS.body, paraSpaceAfter: 8 });
  s.addNotes(
    "The Wallet tab is the Haystack wallet as a user would see it. " +
    "It syncs by itself on an exponential timer, two minutes on average at demo speed and thirty in the product, and the delay is drawn when a sync finishes so nothing the user does moves it (docs/02-design.md, 'Sync scheduling'). " +
    "Each sync is a padded full scan, after which the repo's attacker reads the session log and the page says, in two words, how hidden the addresses and the funded addresses are. " +
    "The dial offers padding 2, 5, 10 or 20, the settings the trained attacker was trained at, and on regtest a share of chain decoys, 0, 10 or 30 percent; Apply asks for confirmation first. " +
    "A new setting applies only to addresses queried after the change, because withdrawing a decoy the server has already seen would mark it as a decoy.");
}

// ---- 10. Demo, lab tab -----------------------------------------------------------------------

{
  const s = content("Lab tab: live payments and restore", "Inside the repo");
  for (const x of halfX) card(s, x, 1.55, halfW, 5.15);
  const rows = (x, w, head, items) => {
    text(s, head, { x, y: 1.8, w, h: 0.5, fontSize: FS.lead, bold: true });
    items.forEach(([label, effect], i) => {
      const y = 2.5 + i * 1.38;
      chip(s, x, y, Math.min(w, 0.13 * label.length + 0.5), label, false);
      text(s, effect, { x, y: y + 0.5, w, h: 0.8, fontSize: FS.label, color: C.text2 });
    });
  };
  rows(halfX[0] + 0.35, halfW - 0.7, "The regtest chain", [
    ["Someone pays the wallet 0.004 BTC", "Lands on the next unused address. The next sync exposes it: nobody pays a decoy."],
    ["Mine a block", "Confirms what is waiting. Both copies must still show the same balance."],
    ["Wallet sends 0.01 BTC", "Broadcast through bitcoind, not the sync server. Its change address is exposed at the next sync."],
  ]);
  rows(halfX[1] + 0.35, halfW - 0.7, "Restore", [
    ["Copy descriptor · Copy ledger", "Together they are the restore set: the descriptor rebuilds the decoys, the ledger keeps their counts."],
    ["Restore with the ledger", "Deletes the wallet database and cache. The next sync sends exactly the same addresses."],
    ["Restore without the ledger", "Counts are lost. At the wrong padding, decoys are added or withdrawn and the score falls."],
  ]);
  s.addNotes(
    "The Lab tab runs a private regtest chain, so you can make things happen while the server watches. " +
    "A payment lands on the next unused address, and because that address goes from no history to some while it is watched, the next sync exposes it; that is a known limit, not a bug. " +
    "Mining a block confirms what is pending, and a send is broadcast through bitcoind rather than the sync server, though its change still lands on an address the wallet watches. " +
    "The restore set is the descriptor plus the ledger file: restoring with the ledger sends exactly the same query, while restoring without it at another padding changes decoys the server has already seen. " +
    "In one measured case, restoring at padding 5 after syncs at 10 and 20 sent 670 scripthashes instead of 1,350 and the headline fell to 2.23 bits (docs/02-design.md, 'What each user action does').");
}

// ---- 11. Getting started ---------------------------------------------------------------------

pres.addSection({ title: "Next steps" });
{
  const s = content("Try it yourself", "Next steps");
  const codeBlock = (y, label, lines) => {
    text(s, label, { x: L.MX, y, w: L.CW, h: 0.45, fontSize: FS.body, bold: true });
    const runs = lines.map((l, i) => ({ text: l, options: { color: l.startsWith("#") ? C.text2 : C.text1, breakLine: i < lines.length - 1 } }));
    const h = 0.3 + lines.length * 0.34;
    s.addText(runs, { shape: pres.ShapeType.roundRect, rectRadius: 0.08, x: L.MX, y: y + 0.5, w: L.CW, h,
      fill: { color: C.background1 }, line: { color: C.accent5 }, fontFace: MONO, fontSize: FS.body, margin: 12, valign: "middle" });
    return y + 0.5 + h;
  };
  const end = codeBlock(1.45, "Five minutes, no build: Python standard library only", [
    "# Why redrawn decoys fail, by the project's own attacker",
    "python3 -m attack strategies",
    "# Six real padded syncs, scored by the same attacker",
    "python3 -m attack score --session tests/fixtures/haystack-session.jsonl \\",
    "    --honeypot tests/fixtures/haystack-honeypot-log.json --tier T1",
  ]);
  codeBlock(end + 0.3, "The demo wallet on any system, with Docker", [
    "git clone https://github.com/yogesh0509/Haystack.git",
    "cd Haystack",
    "docker build -t haystack .",
    "docker run -it --rm -p 127.0.0.1:7878:7878 -v haystack-out:/haystack/out haystack",
  ]);
  s.addNotes(
    "Two ways in. The first needs only Python's standard library and a clone: the strategies table from earlier, and the six padded syncs committed as fixtures, which read 3.32 bits each. " +
    "The second runs the whole demo in Docker on Linux, macOS or Windows: it starts a private regtest chain, gives the wallet a history, and serves the page at 127.0.0.1 port 7878 once the log says it is ready. " +
    "The README notes the build took five and a half minutes on an 8-core machine, and it downloads bitcoind and electrs checked against pinned hashes. " +
    "A native build with cargo is described in the README, and docs/07-walkthrough.md runs every case with its expected output.");
}

// ---- 12. Closing -----------------------------------------------------------------------------

{
  const s = pres.addSlide({ masterName: "DARK", sectionTitle: "Next steps" });
  s.addText("Haystack", { placeholder: "title" });
  s.addText("Private Electrum sync", { placeholder: "body" });
  text(s, REPO_URL, { x: 0.9, y: 4.2, w: 7.4, h: 0.5, fontSize: FS.lead, bold: true, color: C.background1 });
  text(s, [
    { text: "Start with docs/00-problem.md and docs/07-walkthrough.md: every number has a command that reproduces it.", options: { breakLine: true } },
    { text: "Next on the roadmap: an independent lookup server for chain decoys, and attacks on on-chain links and sync timing.", options: { breakLine: true } },
    { text: "GPL-3.0" },
  ], { x: 0.9, y: 4.85, w: 7.3, h: 2.0, fontSize: FS.label, color: C.accent5, paraSpaceAfter: 8 });
  field(s, 8.9, 1.55);
  s.addNotes(
    "Everything shown today is in the repository, and each number has the command that reproduces it, starting from docs/00-problem.md and docs/07-walkthrough.md. " +
    "The roadmap's next items are an independent lookup server so chain decoys can't be named from the sync server's log, and the attacks that aren't built yet: on-chain clustering and sync timing. " +
    "The code is GPL-3.0. Thank you.");
}

// ---- Write, then give the theme its colours --------------------------------------------------
// pptxgenjs writes the two theme fonts but Office's stock palette; scheme colours resolve to the
// palette above only once it is written into ppt/theme/theme1.xml.

async function applyTheme(file, theme) {
  const JSZip = require(require.resolve("jszip", { paths: [require.resolve("pptxgenjs")] }));
  const zip = await JSZip.loadAsync(fs.readFileSync(file));
  const part = "ppt/theme/theme1.xml";
  const slots = ["dk1", "lt1", "dk2", "lt2", "accent1", "accent2", "accent3", "accent4", "accent5", "accent6", "hlink", "folHlink"];
  const scheme = `<a:clrScheme name="${theme.name}">` + slots.map((k) => `<a:${k}><a:srgbClr val="${theme.colors[k]}"/></a:${k}>`).join("") + "</a:clrScheme>";
  const xml = (await zip.file(part).async("string"))
    .replace(/<a:clrScheme\b[\s\S]*?<\/a:clrScheme>/, () => scheme)
    .replace(/(<a:(?:theme|fontScheme)\b[^>]*?\bname=")[^"]*"/g, (_, head) => `${head}${theme.name}"`);
  if (!xml.includes(scheme)) throw new Error("no <a:clrScheme> in the theme part");
  zip.file(part, xml);
  fs.writeFileSync(file, await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" }));
}

(async () => {
  await pres.writeFile({ fileName: OUT });
  await applyTheme(OUT, THEME);
  console.log("wrote", OUT);
})();
