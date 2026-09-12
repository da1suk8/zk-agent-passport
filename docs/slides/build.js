// Builds zk-agent-passport.pptx. The .pptx in this directory is generated, not
// hand-edited: change this file and rebuild, or the next build discards the
// edit.
//
//   cd docs/slides && npm install && npm run build
//
// pptxgenjs is pinned in package.json; 3.12.0 is what the committed deck was
// built with.
const pptxgen = require("pptxgenjs");

const W = 13.333, H = 7.5, M = 0.7, CW = W - 2 * M;

// --- palette -----------------------------------------------------------
const INK    = "0F1024";  // near-black indigo (dark slides)
const INK2   = "1B1E3D";  // raised surface on dark
const INDIGO = "2B2F77";  // primary
const IND_LT = "5257AE";
const LILAC  = "EDEEF7";  // light card surface
const LILAC2 = "DFE1F1";
const GREEN  = "00875F";  // verified / revealed
const GREEN_L= "E2F3EC";
const CORAL  = "C0402A";  // broken / rejected
const CORAL_L= "FBEAE6";
const MUTED  = "6A6F93";
const MINT   = "5FDDAE";  // green that stays legible on indigo
const WHITE  = "FFFFFF";

const F = "Arial";
const FM = "Courier New";

const sh = () => ({ type: "outer", color: INDIGO, blur: 10, offset: 1.5, angle: 90, opacity: 0.12 });

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.author = "Daisuke Iuchi";
pres.title = "zkAgent Passport";

let pageNo = 0;

function slide(opts = {}) {
  const s = pres.addSlide();
  if (opts.dark) s.background = { color: INK };
  return s;
}

function head(s, label, title, dark) {
  s.addText(label, {
    x: M, y: 0.36, w: CW, h: 0.26, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 11, bold: true, charSpacing: 2,
    color: dark ? IND_LT : MUTED,
  });
  s.addText(title, {
    x: M, y: 0.66, w: CW, h: 0.78, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 29, bold: true, color: dark ? WHITE : INDIGO,
    valign: "top",
  });
}

function pageNum(s) {
  pageNo += 1;
  const n = pageNo;
  s.addText(String(n), {
    x: W - 1.15, y: 6.92, w: 0.45, h: 0.28, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 10, color: MUTED, align: "right",
  });
}

function card(s, x, y, w, h, fill) {
  s.addShape(pres.ShapeType.roundRect, {
    x, y, w, h, fill: { color: fill || LILAC }, rectRadius: 0.08, shadow: sh(),
  });
}

function badge(s, x, y, text, fill, color) {
  s.addShape(pres.ShapeType.ellipse, { x, y, w: 0.42, h: 0.42, fill: { color: fill || INDIGO } });
  s.addText(text, {
    x, y, w: 0.42, h: 0.42, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 14, bold: true, color: color || WHITE,
    align: "center", valign: "middle",
  });
}

// --- アイコン ------------------------------------------------------------
// すべて図形だけで描く（外部画像に依存しない）。z = 枠の一辺、fg = 図の色、bg = 抜き色。

// ロボット（AI エージェント）。原点から 1.35k × 1.68k。
function robot(s, x, y, k, c) {
  const p = c || {};
  const head = p.head || INDIGO, part = p.part || IND_LT, eye = p.eye || GREEN, mouth = p.mouth || LILAC2;
  s.addShape(pres.ShapeType.ellipse, { x: x + 0.60 * k, y, w: 0.18 * k, h: 0.18 * k, fill: { color: eye } });
  s.addShape(pres.ShapeType.rect, { x: x + 0.665 * k, y: y + 0.15 * k, w: 0.05 * k, h: 0.2 * k, fill: { color: head } });
  s.addShape(pres.ShapeType.roundRect, { x: x + 0.02 * k, y: y + 0.58 * k, w: 0.11 * k, h: 0.26 * k, fill: { color: part }, rectRadius: 0.03 });
  s.addShape(pres.ShapeType.roundRect, { x: x + 1.24 * k, y: y + 0.58 * k, w: 0.11 * k, h: 0.26 * k, fill: { color: part }, rectRadius: 0.03 });
  s.addShape(pres.ShapeType.roundRect, { x: x + 0.12 * k, y: y + 0.33 * k, w: 1.12 * k, h: 0.88 * k, fill: { color: head }, rectRadius: 0.14 * k });
  s.addShape(pres.ShapeType.ellipse, { x: x + 0.38 * k, y: y + 0.57 * k, w: 0.17 * k, h: 0.17 * k, fill: { color: eye } });
  s.addShape(pres.ShapeType.ellipse, { x: x + 0.81 * k, y: y + 0.57 * k, w: 0.17 * k, h: 0.17 * k, fill: { color: eye } });
  s.addShape(pres.ShapeType.roundRect, { x: x + 0.50 * k, y: y + 0.92 * k, w: 0.36 * k, h: 0.10 * k, fill: { color: mouth }, rectRadius: 0.03 * k });
  s.addShape(pres.ShapeType.rect, { x: x + 0.62 * k, y: y + 1.21 * k, w: 0.12 * k, h: 0.10 * k, fill: { color: part } });
  s.addShape(pres.ShapeType.roundRect, { x: x + 0.30 * k, y: y + 1.30 * k, w: 0.76 * k, h: 0.38 * k, fill: { color: part }, rectRadius: 0.1 * k });
}

// 会社・サービス
function iconBuilding(s, x, y, z, fg, bg) {
  s.addShape(pres.ShapeType.roundRect, { x: x + 0.08 * z, y: y + 0.10 * z, w: 0.84 * z, h: 0.82 * z, fill: { color: fg }, rectRadius: 0.05 * z });
  [[0.22, 0.26], [0.56, 0.26], [0.22, 0.48], [0.56, 0.48]].forEach(([a, b]) =>
    s.addShape(pres.ShapeType.rect, { x: x + a * z, y: y + b * z, w: 0.18 * z, h: 0.14 * z, fill: { color: bg } }));
  s.addShape(pres.ShapeType.rect, { x: x + 0.39 * z, y: y + 0.72 * z, w: 0.18 * z, h: 0.20 * z, fill: { color: bg } });
}

// 検査して絞る（Gateway）
function iconFunnel(s, x, y, z, fg) {
  s.addShape(pres.ShapeType.triangle, { x: x + 0.04 * z, y: y + 0.10 * z, w: 0.92 * z, h: 0.52 * z, fill: { color: fg }, rotate: 180 });
  s.addShape(pres.ShapeType.rect, { x: x + 0.43 * z, y: y + 0.58 * z, w: 0.14 * z, h: 0.32 * z, fill: { color: fg } });
}

// 3 ノード（Committee）
function iconNodes(s, x, y, z, fg, accent) {
  s.addShape(pres.ShapeType.rect, { x: x + 0.20 * z, y: y + 0.28 * z, w: 0.60 * z, h: 0.06 * z, fill: { color: fg } });
  s.addShape(pres.ShapeType.rect, { x: x + 0.47 * z, y: y + 0.30 * z, w: 0.06 * z, h: 0.36 * z, fill: { color: fg } });
  s.addShape(pres.ShapeType.ellipse, { x: x + 0.04 * z, y: y + 0.14 * z, w: 0.30 * z, h: 0.30 * z, fill: { color: fg } });
  s.addShape(pres.ShapeType.ellipse, { x: x + 0.66 * z, y: y + 0.14 * z, w: 0.30 * z, h: 0.30 * z, fill: { color: fg } });
  s.addShape(pres.ShapeType.ellipse, { x: x + 0.35 * z, y: y + 0.62 * z, w: 0.30 * z, h: 0.30 * z, fill: { color: accent } });
}

// 証明・書類
function iconProof(s, x, y, z, fg, bg) {
  s.addShape(pres.ShapeType.roundRect, { x: x + 0.14 * z, y: y + 0.04 * z, w: 0.72 * z, h: 0.92 * z, fill: { color: fg }, rectRadius: 0.05 * z });
  [0.24, 0.40, 0.56].forEach((b) =>
    s.addShape(pres.ShapeType.rect, { x: x + 0.26 * z, y: y + b * z, w: 0.48 * z, h: 0.07 * z, fill: { color: bg } }));
  s.addShape(pres.ShapeType.ellipse, { x: x + 0.36 * z, y: y + 0.70 * z, w: 0.20 * z, h: 0.20 * z, fill: { color: bg } });
}

// 出どころの保証（印）
function iconSeal(s, x, y, z, fg, bg) {
  s.addShape(pres.ShapeType.ellipse, { x, y, w: z, h: z, fill: { color: fg } });
  s.addShape(pres.ShapeType.ellipse, { x: x + 0.14 * z, y: y + 0.14 * z, w: 0.72 * z, h: 0.72 * z, fill: { color: bg } });
  s.addShape(pres.ShapeType.ellipse, { x: x + 0.28 * z, y: y + 0.28 * z, w: 0.44 * z, h: 0.44 * z, fill: { color: fg } });
  s.addShape(pres.ShapeType.ellipse, { x: x + 0.41 * z, y: y + 0.41 * z, w: 0.18 * z, h: 0.18 * z, fill: { color: bg } });
}

// 見せない（目に斜線）
function iconHidden(s, x, y, z, fg, bg) {
  s.addShape(pres.ShapeType.ellipse, { x, y: y + 0.22 * z, w: z, h: 0.56 * z, fill: { color: fg } });
  s.addShape(pres.ShapeType.ellipse, { x: x + 0.34 * z, y: y + 0.34 * z, w: 0.32 * z, h: 0.32 * z, fill: { color: bg } });
  s.addShape(pres.ShapeType.rect, { x: x - 0.02 * z, y: y + 0.44 * z, w: 1.04 * z, h: 0.12 * z, fill: { color: bg }, rotate: -35 });
  s.addShape(pres.ShapeType.rect, { x: x + 0.02 * z, y: y + 0.46 * z, w: 0.96 * z, h: 0.07 * z, fill: { color: fg }, rotate: -35 });
}

// 束縛（錠前）
function iconLock(s, x, y, z, fg, bg) {
  s.addShape(pres.ShapeType.roundRect, { x: x + 0.22 * z, y, w: 0.56 * z, h: 0.60 * z, fill: { color: fg }, rectRadius: 0.12 * z });
  s.addShape(pres.ShapeType.rect, { x: x + 0.33 * z, y: y + 0.22 * z, w: 0.34 * z, h: 0.40 * z, fill: { color: bg } });
  s.addShape(pres.ShapeType.roundRect, { x, y: y + 0.42 * z, w: z, h: 0.58 * z, fill: { color: fg }, rectRadius: 0.08 * z });
  s.addShape(pres.ShapeType.ellipse, { x: x + 0.42 * z, y: y + 0.62 * z, w: 0.16 * z, h: 0.16 * z, fill: { color: bg } });
}

function note(s, y, text, color) {
  s.addText(text, {
    x: M, y, w: CW, h: 0.4, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 13, color: color || INDIGO, italic: true, valign: "middle",
  });
}

// =======================================================================
// 1. TITLE
// =======================================================================
{
  const s = slide({ dark: true });
  const LC = 8.1;  // 左カラム幅（右は印章モチーフ）

  s.addShape(pres.ShapeType.ellipse, { x: 9.1, y: 1.25, w: 4.6, h: 4.6, fill: { color: INK }, line: { color: IND_LT, width: 1.5, transparency: 25 } });
  s.addShape(pres.ShapeType.ellipse, { x: 9.65, y: 1.8, w: 3.5, h: 3.5, fill: { color: INK }, line: { color: IND_LT, width: 1.25, transparency: 50 } });
  s.addShape(pres.ShapeType.ellipse, { x: 10.3, y: 2.45, w: 2.2, h: 2.2, fill: { color: INK2 }, line: { color: GREEN, width: 1.5, transparency: 20 } });
  s.addText("VERIFIED\nWITHOUT\nDISCLOSURE", {
    x: 10.3, y: 2.45, w: 2.2, h: 2.2, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 11, bold: true, charSpacing: 2, color: GREEN,
    align: "center", valign: "middle", lineSpacing: 18,
  });

  s.addText("zk-tokyo  Advanced Cryptography 2026  ·  最終発表", {
    x: M, y: 1.55, w: LC, h: 0.3, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 12, bold: true, charSpacing: 2, color: IND_LT,
  });
  s.addText("zkAgent Passport", {
    x: M, y: 1.95, w: LC, h: 1.05, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 52, bold: true, color: WHITE,
  });
  s.addText("評価の中身も取引先も渡さずに、「この領域で、宣言した構成のまま、条件を満たしている」ことだけをサービスに証明する", {
    x: M, y: 3.08, w: LC, h: 0.92, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 17, color: LILAC2, lineSpacing: 28,
  });
  s.addText("「実績はエージェントではなく、その構成に付く」", {
    x: M, y: 4.2, w: LC, h: 0.5, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 19, bold: true, color: GREEN, valign: "middle",
  });

  s.addText("Daisuke Iuchi　/　Group 3・Issue #124", {
    x: M, y: 5.3, w: LC, h: 0.32, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 14, color: WHITE,
  });
  s.addText("github.com/da1suk8/zk-agent-passport", {
    x: M, y: 5.7, w: LC, h: 0.32, isTextBox: true, margin: 0,
    fontFace: FM, fontSize: 11, color: MUTED,
  });
  s.addNotes("0:00-0:10 掴み。名前を言ったら、すぐ下の 1 行をそのまま読む。『評価の中身も取引先も渡さずに、この領域で宣言した構成のまま条件を満たしていることだけを証明する』。何を作ったのかはこの 1 行で足りる。緑の 1 文は Manifest binding のキャッチで、最後にもう一度出す。");
}

// =======================================================================
// 2. CROWD
// =======================================================================
{
  const s = slide();
  head(s, "01 ─ 背景", "AI エージェントは山ほどある。どれに任せるか");

  // --- 候補がずらりと並ぶ -----------------------------------------------
  const gw = 7.2, gy = 1.9, gh = 3.2;
  card(s, M, gy, gw, gh, LILAC);
  for (let i = 0; i < 8; i += 1) {
    const col = i % 4, row = Math.floor(i / 4);
    const cx = M + 0.9 + col * 1.8, y = gy + 0.3 + row * 1.1;
    const alt = (i + row) % 2 === 1;
    robot(s, cx - 0.3375, y, 0.5, alt ? { head: IND_LT, part: "9297D8", eye: GREEN, mouth: WHITE } : null);
  }
  s.addText("どれも「この分野で実績があります」と言う", {
    x: M + 0.3, y: gy + 2.45, w: gw - 0.6, h: 0.4, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 12.5, color: MUTED, align: "center",
  });

  // --- 選ぶ側 -----------------------------------------------------------
  const dx = M + gw + 0.55, dw = M + CW - dx;
  s.addShape(pres.ShapeType.roundRect, { x: dx, y: gy, w: dw, h: gh, fill: { color: INDIGO }, rectRadius: 0.06, shadow: sh() });
  iconBuilding(s, dx + 0.32, gy + 0.26, 0.46, WHITE, INDIGO);
  s.addShape(pres.ShapeType.roundRect, { x: dx + 0.88, y: gy + 0.28, w: 1.7, h: 0.4, fill: { color: WHITE }, rectRadius: 0.06 });
  s.addText("予約サービス", {
    x: dx + 0.88, y: gy + 0.28, w: 1.7, h: 0.4, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 12.5, bold: true, color: INDIGO, align: "center", valign: "middle",
  });
  s.addText("？", {
    x: dx + 0.32, y: gy + 0.95, w: dw - 0.64, h: 0.95, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 46, bold: true, color: MINT, align: "center", valign: "middle",
  });
  s.addText("どれに任せてよいか、基準がない", {
    x: dx + 0.32, y: gy + 2.0, w: dw - 0.64, h: 0.8, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 16, bold: true, color: WHITE, align: "center", valign: "middle", lineSpacing: 24,
  });

  // --- 帯 ---------------------------------------------------------------
  s.addShape(pres.ShapeType.roundRect, { x: M, y: 5.35, w: CW, h: 0.82, fill: { color: LILAC }, rectRadius: 0.08 });
  s.addText("手がかりになりそうなのは、他所のサービスで積んだ実績", {
    x: M + 0.4, y: 5.35, w: CW - 0.8, h: 0.82, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 16, bold: true, color: INDIGO, valign: "middle",
  });
  pageNum(s);
  s.addNotes("0:10-0:25 背景。まず母集団の話。旅行予約を代行する AI エージェントは今後いくらでも出てくる。予約サービスから見ると、どれに任せてよいかを決める基準がない。どれも「実績があります」と言う。手がかりになるのは他所で積んだ実績だろう、と言って次の 1 枚へ。ここは 15 秒で通す。");
}

// =======================================================================
// 3. SCENE
// =======================================================================
{
  const s = slide();
  head(s, "02 ─ 問題提起", "「実績があります」と言われても、確かめようがない");

  const figY = 1.95, figH = 2.9;

  // --- AI エージェント --------------------------------------------------
  const aw = 5.4;
  s.addShape(pres.ShapeType.roundRect, {
    x: M, y: figY, w: aw, h: figH, fill: { color: "F8F9FD" }, rectRadius: 0.06,
    line: { color: INDIGO, width: 2.25 }, shadow: sh(),
  });
  s.addShape(pres.ShapeType.roundRect, { x: M + 0.32, y: figY + 0.28, w: 1.4, h: 0.4, fill: { color: INDIGO }, rectRadius: 0.06 });
  s.addText("AI Agent", {
    x: M + 0.32, y: figY + 0.28, w: 1.4, h: 0.4, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 12.5, bold: true, color: WHITE, align: "center", valign: "middle",
  });
  s.addText("travel-agent-01", {
    x: M + 1.85, y: figY + 0.28, w: aw - 2.15, h: 0.4, isTextBox: true, margin: 0,
    fontFace: FM, fontSize: 10.5, bold: true, color: MUTED, align: "right", valign: "middle",
  });

  robot(s, M + 0.42, figY + 0.92, 0.85);

  s.addText("旅行予約を代行する AI エージェント", {
    x: M + 1.85, y: figY + 0.9, w: 3.23, h: 0.8, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 12.5, color: "3A3F63", lineSpacing: 21,
  });
  s.addText("「他のサービスで実績があります」", {
    x: M + 1.85, y: figY + 1.8, w: 3.23, h: 0.5, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 14.5, bold: true, color: INDIGO, valign: "middle",
  });
  s.addText("— 本人の自己申告", {
    x: M + 1.85, y: figY + 2.32, w: 3.23, h: 0.3, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 10.5, color: MUTED,
  });

  s.addShape(pres.ShapeType.rightArrow, { x: M + aw + 0.12, y: figY + (figH - 0.36) / 2, w: 0.55, h: 0.36, fill: { color: CORAL } });

  // --- 予約サービス（問いと、2 つの困りごと）----------------------------
  const dx = M + aw + 0.79, dw = M + CW - dx;
  s.addShape(pres.ShapeType.roundRect, { x: dx, y: figY, w: dw, h: figH, fill: { color: INDIGO }, rectRadius: 0.06, shadow: sh() });
  iconBuilding(s, dx + 0.32, figY + 0.24, 0.46, WHITE, INDIGO);
  s.addShape(pres.ShapeType.roundRect, { x: dx + 0.85, y: figY + 0.28, w: 1.7, h: 0.4, fill: { color: WHITE }, rectRadius: 0.06 });
  s.addText("予約サービス", {
    x: dx + 0.85, y: figY + 0.28, w: 1.7, h: 0.4, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 12.5, bold: true, color: INDIGO, align: "center", valign: "middle",
  });
  s.addText("この Agent は初めて", {
    x: dx + 2.7, y: figY + 0.28, w: dw - 3.02, h: 0.4, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 11, color: LILAC2, align: "right", valign: "middle",
  });
  s.addText("「この AI エージェントに予約を任せてよいか？」", {
    x: dx + 0.32, y: figY + 0.88, w: dw - 0.64, h: 0.5, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 15, bold: true, color: WHITE, align: "center", valign: "middle",
  });
  ["自己申告は確かめられない", "確かめるには履歴を全部もらうしかない"].forEach((t, i) => {
    const y = figY + 1.6 + i * 0.62;
    s.addShape(pres.ShapeType.roundRect, { x: dx + 0.32, y, w: dw - 0.64, h: 0.52, fill: { color: "222657" }, rectRadius: 0.05 });
    s.addText("✗", {
      x: dx + 0.5, y, w: 0.3, h: 0.52, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 14, bold: true, color: "FF8A75", valign: "middle",
    });
    s.addText(t, {
      x: dx + 0.88, y, w: dw - 1.2, h: 0.52, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 13, bold: true, color: WHITE, valign: "middle",
    });
  });

  // --- 帯 ---------------------------------------------------------------
  s.addShape(pres.ShapeType.roundRect, { x: M, y: 5.3, w: CW, h: 0.82, fill: { color: LILAC }, rectRadius: 0.08 });
  s.addText("ほしいのは、「他所で積んだ実績を、検証できる形で持ち運ぶこと」", {
    x: M + 0.4, y: 5.3, w: CW - 0.8, h: 0.82, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 16, bold: true, color: INDIGO, valign: "middle",
  });
  pageNum(s);
  s.addNotes("0:25-0:45 問題提起。左のロボットを指して、話しているのは人や代理店ではなくソフトウェアの AI エージェントだと最初に分からせる。旅行予約を代行するこの Agent が、予約サービスに来る。この Agent を信頼してよいか、という問いを立てる。ここで一度切って『しかし』と続け、サービス側の箱の 2 つを指す。自己申告は確かめられない。かといって確かめようとすると履歴を全部もらうことになり、取引先も低評価も一緒に渡ってくる。この板挟みが出発点。だから『他所で積んだ実績を検証できる形で持ち運ぶ』が要る、と言って次へ。具体的な会社名と点数はデモまで出さない。");
}

// =======================================================================
// 4. SWAPPABLE
// =======================================================================
{
  const s = slide();
  head(s, "03 ─ AI 固有の難しさ", "同じ名前のまま、モデルも権限も入れ替えられる");

  const rows = [
    ["modelId", "gpt-demo-v1", "gpt-demo-v2"],
    ["systemPromptHash", "予約案を提案する", "予約変更まで指示"],
    ["toolPolicyHash", "検索のみ", "変更 API を追加"],
    ["permissionScope", "travel-booking", "travel-booking-admin"],
  ];
  const bw = (CW - 0.5) / 2, by = 1.95, bh = 3.35;
  [0, 1].forEach((side) => {
    const bxx = M + side * (bw + 0.5);
    const accent = side === 0 ? INDIGO : CORAL;
    s.addShape(pres.ShapeType.roundRect, {
      x: bxx, y: by, w: bw, h: bh, fill: { color: side === 0 ? "F8F9FD" : "FEF7F5" },
      rectRadius: 0.06, line: { color: accent, width: 2.25 }, shadow: sh(),
    });
    robot(s, bxx + 0.3, by + 0.14, 0.32, side === 0 ? null : { head: CORAL, part: "E08A76", eye: WHITE, mouth: CORAL_L });
    s.addShape(pres.ShapeType.roundRect, { x: bxx + 0.85, y: by + 0.22, w: 1.75, h: 0.42, fill: { color: accent }, rectRadius: 0.06 });
    s.addText(side === 0 ? "昨日の Agent" : "今日の Agent", {
      x: bxx + 0.85, y: by + 0.22, w: 1.75, h: 0.42, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 12.5, bold: true, color: WHITE, align: "center", valign: "middle",
    });
    s.addText("travel-agent-01", {
      x: bxx + 2.72, y: by + 0.22, w: bw - 3.02, h: 0.42, isTextBox: true, margin: 0,
      fontFace: FM, fontSize: 10.5, bold: true, color: MUTED, align: "right", valign: "middle",
    });
    rows.forEach(([k, a, b], i) => {
      const y = by + 0.92 + i * 0.56, w = bw - 0.6, cx = bxx + 0.3;
      s.addShape(pres.ShapeType.roundRect, {
        x: cx, y, w, h: 0.48, rectRadius: 0.05,
        fill: { color: side === 0 ? LILAC : CORAL_L },
      });
      s.addText(k, {
        x: cx + 0.16, y, w: 2.0, h: 0.48, isTextBox: true, margin: 0,
        fontFace: FM, fontSize: 9.5, bold: true, color: side === 0 ? INDIGO : CORAL, valign: "middle",
      });
      s.addText(side === 0 ? a : b, {
        x: cx + 2.2, y, w: w - 2.36, h: 0.48, isTextBox: true, margin: 0,
        fontFace: F, fontSize: 11, bold: side === 1, color: side === 0 ? "3A3F63" : CORAL,
        align: "right", valign: "middle",
      });
    });
  });

  s.addShape(pres.ShapeType.roundRect, { x: M, y: 5.55, w: CW, h: 1.0, fill: { color: CORAL }, rectRadius: 0.08, shadow: sh() });
  s.addText([
    { text: "名前は同じまま、できることが変わる。実績を名前に付けると意味を失う。", options: { fontSize: 14.5, bold: true, color: WHITE, breakLine: true } },
    { text: "かといって、更新のたびに実績を捨てるのも現実的ではない。", options: { fontSize: 11.5, color: "FBEAE6" } },
  ], {
    x: M + 0.4, y: 5.55, w: CW - 0.8, h: 1.0, isTextBox: true, margin: 0, valign: "middle", lineSpacing: 23,
  });
  pageNum(s);
  s.addNotes("0:45-1:05 問題②。人間にはない問題。昨日と今日で名前は同じ travel-agent-01 のまま、モデルも指示もツールも権限も入れ替わっている。実績を名前に紐付けると意味を失う。かといって更新のたびに実績を捨てるのも困る、という緊張をここで作っておくと、7 枚目の Version Policy が効く。");
}

// =======================================================================
// 5. SOLUTION
// =======================================================================
{
  const s = slide();
  head(s, "04 ─ 提案", "そこで作ったのが zkAgent Passport");

  s.addShape(pres.ShapeType.roundRect, { x: M, y: 1.9, w: CW, h: 1.1, fill: { color: INDIGO }, rectRadius: 0.08, shadow: sh() });
  s.addText("評価の詳細を渡さずに、「この領域で、宣言した構成のまま、サービスの求める条件を満たしている」ことだけを証明する仕組み", {
    x: M + 0.5, y: 1.9, w: CW - 1.0, h: 1.1, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 17, bold: true, color: WHITE, valign: "middle", align: "center", lineSpacing: 27,
  });

  const pillars = [
    ["「確かめられない」への答え", "出どころを保証する", "登録された取引先だけが署名付きの Receipt を出せる"],
    ["「全部渡すことになる」への答え", "中身を見せずに証明する", "合計点も件数も渡さず、条件を満たすことだけを証明する"],
    ["「入れ替えられる」への答え", "構成に束縛する", "実績は名前ではなく、構成のハッシュに結び付く"],
  ];
  const cw = 3.78, gap = (CW - cw * 3) / 2, top = 3.3, ch = 2.45;
  pillars.forEach(([tag, t, d], i) => {
    const x = M + i * (cw + gap);
    const own = i === 2;  // 3 つ目が独自点
    card(s, x, top, cw, ch, own ? INDIGO : LILAC);
    const ig = own ? WHITE : GREEN, ib = own ? INDIGO : LILAC;
    if (i === 0) iconSeal(s, x + cw - 0.78, top + 0.24, 0.46, ig, ib);
    if (i === 1) iconHidden(s, x + cw - 0.78, top + 0.24, 0.46, ig, ib);
    if (i === 2) iconLock(s, x + cw - 0.75, top + 0.23, 0.42, ig, ib);
    s.addShape(pres.ShapeType.roundRect, { x: x + 0.32, y: top + 0.28, w: 2.4, h: 0.38, fill: { color: own ? WHITE : GREEN_L }, rectRadius: 0.05 });
    s.addText(tag, {
      x: x + 0.32, y: top + 0.28, w: 2.4, h: 0.38, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 10, bold: true, color: own ? INDIGO : GREEN, align: "center", valign: "middle",
    });
    s.addText(t, {
      x: x + 0.32, y: top + 0.82, w: cw - 0.64, h: 0.45, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 17, bold: true, color: own ? WHITE : INDIGO,
    });
    s.addText(d, {
      x: x + 0.32, y: top + 1.36, w: cw - 0.64, h: 0.95, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 13, color: own ? LILAC2 : "3A3F63", lineSpacing: 21,
    });
  });

  pageNum(s);
  s.addNotes("1:05-1:30 提案。ここで初めて名前を出す。定義を 1 文で読み上げてから、3 枚のカードがそれぞれ前の 2 枚で挙げた問題への答えになっていることを指差す。3 つ目が独自点だと明言しておくと、後ろの Manifest binding のスライドが素直に入る。");
}

// =======================================================================
// 6. WHAT IS PROVEN
// =======================================================================
{
  const s = slide();
  head(s, "05 ─ 開示", "予約サービスに渡るのは、164 バイトの証明だけ");

  iconBuilding(s, M, 1.45, 0.32, INDIGO, WHITE);
  s.addText("予約サービス = 証明を受け取って判断する側（構成図では Service）", {
    x: M + 0.44, y: 1.43, w: CW - 0.44, h: 0.36, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 11.5, color: MUTED, valign: "middle",
  });

  s.addShape(pres.ShapeType.roundRect, { x: M, y: 1.9, w: CW, h: 0.8, fill: { color: INK }, rectRadius: 0.08, shadow: sh() });
  s.addText("nullifier = Hash( agentSecret , verifierId )　←　サービスごとに別の値になる", {
    x: M + 0.3, y: 1.9, w: CW - 0.6, h: 0.8, isTextBox: true, margin: 0,
    fontFace: FM, fontSize: 14, bold: true, color: GREEN, valign: "middle", align: "center",
  });

  const cw2 = (CW - 0.45) / 2, top = 2.95, ch = 2.95;
  card(s, M, top, cw2, ch, GREEN_L);
  iconProof(s, M + cw2 - 0.92, top + 0.26, 0.6, GREEN, GREEN_L);
  s.addText("予約サービスが受け取るもの", {
    x: M + 0.35, y: top + 0.3, w: cw2 - 0.7, h: 0.42, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 17, bold: true, color: GREEN,
  });
  s.addText([
    { text: "Groth16 の証明 1 つ（164 bytes）", options: { bullet: true, breakLine: true } },
    { text: "公開入力 20 個", options: { bullet: true, breakLine: true } },
    { text: "そのサービス専用の nullifier", options: { bullet: true } },
  ], {
    x: M + 0.35, y: top + 0.88, w: cw2 - 0.7, h: 1.9, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 13.5, color: "23483C", lineSpacing: 22, paraSpaceAfter: 10,
  });

  card(s, M + cw2 + 0.45, top, cw2, ch, LILAC);
  iconHidden(s, M + 2 * cw2 + 0.45 - 0.98, top + 0.3, 0.62, INDIGO, LILAC);
  s.addText("予約サービスが受け取らないもの", {
    x: M + cw2 + 0.8, y: top + 0.3, w: cw2 - 0.7, h: 0.42, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 17, bold: true, color: INDIGO,
  });
  s.addText([
    { text: "個別の評価・取引先の名前・合計点", options: { bullet: true, breakLine: true } },
    { text: "Receipt の件数", options: { bullet: true, breakLine: true } },
    { text: "証明書そのもの", options: { bullet: true, breakLine: true } },
    { text: "passportCommitment・agentSecret", options: { bullet: true } },
  ], {
    x: M + cw2 + 0.8, y: top + 0.88, w: cw2 - 0.7, h: 1.9, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 13.5, color: "3A3F63", lineSpacing: 22, paraSpaceAfter: 10,
  });

  pageNum(s);
  s.addNotes("1:30-1:50 開示。まず見出しの下の 1 行で「サービス」が何を指すかを言う（1 枚目の予約サービスと同じもので、次の構成図では Service（検証者））。そのうえで左右の対比を読み上げる。証明書そのものが渡らないことと、Agent 固有の値が nullifier だけであることの 2 点を強調する。デモの右パネルがちょうどこの対比になっている、と繋げる。");
}

// =======================================================================
// 7. ARCHITECTURE
// =======================================================================
{
  const s = slide();
  head(s, "06 ─ 構成", "仕事の評価が、証明になるまでの 5 ステップ");

  const steps = [
    ["1", "Task Provider\n（取引先）", "評価を出した取引先。デモでは A・B・C の 3 社"],
    ["2", "Input Gateway", "6 つの検査を通し、3 ノードへ分割"],
    ["3", "Reputation Committee", "部分和から証明書を作り、2-of-3 で署名"],
    ["4", "Agent", "秘密と Manifest を持ち、証明を作る"],
    ["5", "Service（検証者）", "予約サービス。Policy と nonce を出す"],
  ];
  const bw = 2.0, gap = (CW - bw * 5) / 4, top = 1.95, bh = 2.45;
  steps.forEach(([n, t, d], i) => {
    const x = M + i * (bw + gap);
    const isAgent = i === 3;
    card(s, x, top, bw, bh, isAgent ? INDIGO : LILAC);
    const fg = isAgent ? WHITE : INDIGO, bgc = isAgent ? INDIGO : LILAC;
    const ix = x + 0.5, iy = top + 0.22, iz = 0.46;
    if (i === 0) iconBuilding(s, ix, iy, iz, fg, bgc);
    if (i === 1) iconFunnel(s, ix, iy, iz, fg);
    if (i === 2) iconNodes(s, ix, iy, iz, fg, GREEN);
    if (i === 3) robot(s, ix + 0.02, iy + 0.02, 0.29, { head: WHITE, part: LILAC2, eye: GREEN, mouth: INDIGO });
    if (i === 4) iconBuilding(s, ix, iy, iz, fg, bgc);
    badge(s, x + 1.08, top + 0.24, n, isAgent ? WHITE : INDIGO, isAgent ? INDIGO : WHITE);
    s.addText(t, {
      x: x + 0.14, y: top + 0.86, w: bw - 0.28, h: 0.62, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 13, bold: true, color: isAgent ? WHITE : INDIGO, align: "center",
    });
    s.addText(d, {
      x: x + 0.14, y: top + 1.52, w: bw - 0.28, h: 0.85, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 10, color: isAgent ? LILAC2 : "3A3F63", align: "center", lineSpacing: 15,
    });
    if (i < 4) {
      s.addShape(pres.ShapeType.rightArrow, {
        x: x + bw + (gap - 0.4) / 2, y: top + 1.0, w: 0.4, h: 0.34,
        fill: { color: i === 3 ? GREEN : IND_LT },
      });
    }
  });

  s.addText("取引先の 3 社はデモの都合。Committee の 3 ノードは回路の固定値。", {
    x: M, y: 4.46, w: CW, h: 0.3, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 10.5, color: MUTED,
  });

  s.addShape(pres.ShapeType.roundRect, { x: M, y: 4.86, w: CW, h: 0.78, fill: { color: GREEN_L }, rectRadius: 0.08 });
  s.addText("証明書は Agent で止まる。4 → 5 が運ぶのは、証明と公開入力 20 個だけ。", {
    x: M + 0.35, y: 4.86, w: CW - 0.7, h: 0.78, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 15, bold: true, color: GREEN, valign: "middle",
  });

  s.addShape(pres.ShapeType.roundRect, { x: M, y: 5.8, w: CW, h: 0.8, fill: { color: LILAC }, rectRadius: 0.08 });
  s.addText("Go 1.25（外部サービス不要）　·　Groth16 / BN254（gnark）　·　Poseidon2　·　Committee 署名は回路内で検証　·　集計は加算的秘密分散", {
    x: M + 0.35, y: 5.8, w: CW - 0.7, h: 0.8, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 11.5, color: "3A3F63", valign: "middle",
  });
  pageNum(s);
  s.addNotes("1:50-2:25 構成。左から順に「誰が何をするか」を追う。1 の Task Provider は取引先、つまり仕事を依頼して評価を出した会社で、デモでは Provider A・B・C の 3 社。5 の Service は 1 枚目から出ている予約サービスそのもの。ここで次のデモに出る名前を全部そろえておく。「3」が 2 回出るので、凡例の 1 行を指して区別を言う（Provider の 3 はデモの社数、Committee の 3 は回路の固定値）。Provider が署名付き Receipt を出し、Gateway が検査して評価を 3 分割、Committee が部分和から証明書を作る。Agent はそれを自分の中に持ったまま証明だけをサービスに出す。MPC の出力を ZK で開く、というのが Week 6 のスタック設計そのもの。");
}

// =======================================================================
// 8. MANIFEST BINDING
// =======================================================================
{
  const s = slide();
  head(s, "07 ─ 独自点", "実績は名前ではなく、この 4 項目に付く");

  // ---- the Agent box -------------------------------------------------
  const bx = 6.2, by = 1.95, bh = 3.5;
  s.addShape(pres.ShapeType.roundRect, {
    x: M, y: by, w: bx, h: bh, fill: { color: "F8F9FD" }, rectRadius: 0.06,
    line: { color: INDIGO, width: 2.25 }, shadow: sh(),
  });
  robot(s, M + 0.3, by + 0.14, 0.32, null);
  s.addShape(pres.ShapeType.roundRect, { x: M + 0.85, y: by + 0.22, w: 1.55, h: 0.42, fill: { color: INDIGO }, rectRadius: 0.06 });
  s.addText("AI Agent", {
    x: M + 0.85, y: by + 0.22, w: 1.55, h: 0.42, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 13, bold: true, color: WHITE, align: "center", valign: "middle",
  });
  s.addText("実績が結び付くのは、この 4 項目だけ", {
    x: M + 2.55, y: by + 0.22, w: bx - 2.85, h: 0.42, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 11.5, color: MUTED, valign: "middle",
  });

  const fields = [
    ["modelId", "どのモデルで動くか", "gpt-demo-v1 → v2", GREEN],
    ["systemPromptHash", "どんな指示で動くか", "変更なし", MUTED],
    ["toolPolicyHash", "どのツールを使えるか", "変更なし", MUTED],
    ["permissionScope", "どこまで操作してよいか", "拡大は許可外", CORAL],
  ];
  fields.forEach(([k, gloss, state, c], i) => {
    const y = by + 0.98 + i * 0.62, w = bx - 0.6, cx = M + 0.3;
    s.addShape(pres.ShapeType.roundRect, {
      x: cx, y, w, h: 0.54, rectRadius: 0.06,
      fill: { color: c === MUTED ? LILAC : (c === GREEN ? GREEN_L : CORAL_L) },
    });
    s.addText(k, {
      x: cx + 0.16, y, w: 1.95, h: 0.54, isTextBox: true, margin: 0,
      fontFace: FM, fontSize: 10.5, bold: true, color: INDIGO, valign: "middle",
    });
    s.addText(gloss, {
      x: cx + 2.15, y, w: 1.9, h: 0.54, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 11, color: "3A3F63", valign: "middle",
    });
    s.addText(state, {
      x: cx + 4.05, y, w: w - 4.21, h: 0.54, isTextBox: true, margin: 0,
      fontFace: i === 0 ? FM : F, fontSize: i === 0 ? 10 : 11, bold: true,
      color: c, align: "right", valign: "middle",
    });
  });

  // ---- right column --------------------------------------------------
  const rx = M + bx + 0.35, rw = CW - bx - 0.35;
  card(s, rx, by, rw, 1.55, LILAC);
  s.addText("Manifest Version Policy", {
    x: rx + 0.3, y: by + 0.24, w: rw - 0.6, h: 0.38, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 15, bold: true, color: INDIGO,
  });
  s.addText("変更してよい項目のビットマスクと、許可リストの Merkle root。どちらも policyHash に束縛される。", {
    x: rx + 0.3, y: by + 0.68, w: rw - 0.6, h: 0.8, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 12, color: "3A3F63", lineSpacing: 19,
  });

  s.addShape(pres.ShapeType.roundRect, { x: rx, y: by + 1.75, w: rw, h: 0.82, fill: { color: GREEN }, rectRadius: 0.08 });
  s.addText("モデルを差し替えても、許可された範囲なら実績は残る", {
    x: rx + 0.3, y: by + 1.75, w: rw - 0.6, h: 0.82, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 13, bold: true, color: WHITE, valign: "middle", lineSpacing: 19,
  });
  s.addShape(pres.ShapeType.roundRect, { x: rx, y: by + 2.68, w: rw, h: 0.82, fill: { color: CORAL }, rectRadius: 0.08 });
  s.addText("許可外の変更は、Agent がそもそも証明を作れない", {
    x: rx + 0.3, y: by + 2.68, w: rw - 0.6, h: 0.82, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 13, bold: true, color: WHITE, valign: "middle", lineSpacing: 19,
  });

  // ---- the hash line -------------------------------------------------
  s.addShape(pres.ShapeType.roundRect, { x: M, y: 5.72, w: CW, h: 0.8, fill: { color: INK }, rectRadius: 0.08, shadow: sh() });
  s.addText("manifestCommitment = Hash( modelId , systemPromptHash , toolPolicyHash , permissionScope )", {
    x: M + 0.3, y: 5.72, w: CW - 0.6, h: 0.8, isTextBox: true, margin: 0,
    fontFace: FM, fontSize: 14, bold: true, color: GREEN, valign: "middle", align: "center",
  });
  pageNum(s);
  s.addNotes("2:25-2:45 独自点。ここが主役。3 枚目で見せた箱と同じ図に戻ってくる。左の箱を指しながら「実績が付くのは名前ではなくこの 4 項目です」と言う。モデルを v2 にしても Policy が許していれば証明は通る、permissionScope の拡大は許可外なので Agent 側で証明を作れない、と 2 つを対にして説明する。");
}

// =======================================================================
// 9. DEMO
// =======================================================================
{
  const s = slide();
  head(s, "08 ─ デモ", "実際に動かして、6 つの問いに答える");

  s.addShape(pres.ShapeType.roundRect, { x: M, y: 1.82, w: CW, h: 1.0, fill: { color: INDIGO }, rectRadius: 0.08, shadow: sh() });
  robot(s, M + 0.36, 1.96, 0.42, { head: WHITE, part: LILAC2, eye: GREEN, mouth: INDIGO });
  s.addText([
    { text: "travel-agent-01 の実績 — 取引先 3 社（Provider A・B・C）から 5 点・4 点・5 点、合計 14 点", options: { fontSize: 13.5, bold: true, color: WHITE, breakLine: true } },
    { text: "予約サービスの条件 — この領域で 12 点以上・3 件以上・宣言した構成のまま。合計点も取引先も渡さずに示せるか。", options: { fontSize: 11.5, color: LILAC2 } },
  ], {
    x: M + 1.2, y: 1.82, w: CW - 1.6, h: 1.0, isTextBox: true, margin: 0, valign: "middle", lineSpacing: 24,
  });

  const items = [
    ["1", "中身を見せずに合格する", "できる（合計点も取引先も渡さない）", GREEN],
    ["2", "自作自演の高評価を防ぐ", "できない（Gateway が弾く）", CORAL],
    ["3", "モデルを更新しても実績は残る", "使える（Policy が許した範囲なら）", GREEN],
    ["4", "権限をこっそり広げると失格", "通らない（Agent 側で止まる）", CORAL],
    ["5", "証明のコピーは使えない", "使えない（nonce）", CORAL],
    ["6", "2 つのサービスが突き合わせても追えない", "分からない（nullifier が別値）", GREEN],
  ];
  const cw2 = (CW - 0.4) / 2, rh = 1.0, top = 3.02;
  items.forEach(([n, t, d, c], i) => {
    const col = i % 2, row = Math.floor(i / 2);
    const x = M + col * (cw2 + 0.4), y = top + row * (rh + 0.19);
    card(s, x, y, cw2, rh, LILAC);
    badge(s, x + 0.28, y + (rh - 0.42) / 2, n, c, WHITE);
    s.addText(t, {
      x: x + 0.88, y: y + 0.11, w: cw2 - 1.15, h: 0.3, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 13.5, bold: true, color: INDIGO,
    });
    s.addText(d, {
      x: x + 0.88, y: y + 0.42, w: cw2 - 1.15, h: 0.44, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 11, color: "3A3F63", lineSpacing: 15
    });
  });

  pageNum(s);
  s.addNotes("2:45-3:45 デモ。まず帯の 2 行を読む。上が Agent 側の実績（取引先 3 社から 5・4・5、合計 14 点）、下が予約サービス側の条件（12 点以上・3 件以上・宣言した構成のまま）。この 2 つを突き合わせるのがデモで、名前も数字も画面の表示と一致する。あとは画面のボタンを ① から ⑥ まで上から押すだけ。各ボタンが条件の設定・実行・答えの表示までやる。③④が Manifest binding の表と裏、⑥ が unlinkability、②⑤ が『暗号で解けるもの／解けないもの』の線引き。見える / 見えないの対比は「Service から何が見えるか」タブを開いて話す（そこに 14・5/4/5・取引先名と、唯一残る限界も出る）。押していたら ② と ⑤ を飛ばす。ブラウザ 1 枚・外部 CDN なしは口頭で。");
}

// =======================================================================
// 10. CLOSING
// =======================================================================
{
  const s = slide({ dark: true });
  s.addText("まとめ — いま動いているもの", {
    x: M, y: 0.66, w: CW, h: 0.6, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 29, bold: true, color: WHITE,
  });

  const lines = [
    "合計点も取引先も渡さずに、条件を満たしていることだけを示せる",
    "実績は名前ではなく、モデル・指示・ツール・権限に結び付く",
    "2 つのサービスが記録を突き合わせても、同じ Agent だとは分からない",
  ];
  lines.forEach((t, i) => {
    const y = 1.72 + i * 0.8;
    s.addShape(pres.ShapeType.roundRect, { x: M, y, w: CW, h: 0.66, fill: { color: INK2 }, rectRadius: 0.08 });
    s.addShape(pres.ShapeType.ellipse, { x: M + 0.32, y: y + 0.23, w: 0.2, h: 0.2, fill: { color: GREEN } });
    s.addText(t, {
      x: M + 0.72, y, w: CW - 1.1, h: 0.66, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 15, color: LILAC2, valign: "middle",
    });
  });

  s.addText("ここまでが、いま動いているもの。残りは、その値段と限界の話です。", {
    x: M, y: 4.15, w: CW, h: 0.32, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 12.5, color: MUTED, align: "center",
  });

  s.addText("「実績はエージェントではなく、その構成に付く」", {
    x: M, y: 4.62, w: CW, h: 0.8, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 27, bold: true, color: GREEN, align: "center",
  });

  s.addText("github.com/da1suk8/zk-agent-passport", {
    x: M, y: 5.62, w: CW, h: 0.4, isTextBox: true, margin: 0,
    fontFace: FM, fontSize: 15, color: WHITE, align: "center",
  });
  s.addText("go run ./cmd/web　でブラウザデモ　·　go test ./...　で 32 ケース　·　go run ./cmd/bench　で計測", {
    x: M, y: 6.05, w: CW, h: 0.4, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 12, color: MUTED, align: "center",
  });
  pageNum(s);
  s.addNotes("3:45-4:00 まとめ。デモの直後、見たばかりのうちに主張を 3 行で確定させる。3 行はデモの ①（中身を見せずに合格）・③④（構成に束縛）・⑥（突き合わせても追えない）にそのまま対応する。キャッチをもう一度出して、『残りは値段と限界の話です』と言って次の 2 枚へ渡す。ここが締めではないので、余韻を作らず短く切る。");
}

// =======================================================================
// 11. NUMBERS
// =======================================================================
{
  const s = slide();
  head(s, "09 ─ 数字", "プライバシーの値段は 55 ミリ秒");

  s.addText("Apple Silicon Mac での実測　—　go run ./cmd/bench -n 20", {
    x: M, y: 1.45, w: CW, h: 0.3, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 11.5, color: MUTED,
  });

  const stats = [
    ["28,596", "制約数（Groth16 / BN254）"],
    ["55 ms", "証明の生成（中央値）"],
    ["< 1 ms", "証明の検証"],
    ["164 bytes", "証明のサイズ"],
  ];
  const sw = (CW - 0.36 * 3) / 4;
  stats.forEach(([v, l], i) => {
    const x = M + i * (sw + 0.36);
    card(s, x, 1.9, sw, 1.25, i === 0 ? INDIGO : LILAC);
    s.addText(v, {
      x: x + 0.15, y: 1.98, w: sw - 0.3, h: 0.68, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 32, bold: true, color: i === 0 ? WHITE : INDIGO, align: "center",
    });
    s.addText(l, {
      x: x + 0.15, y: 2.64, w: sw - 0.3, h: 0.4, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 11, color: i === 0 ? LILAC2 : MUTED, align: "center",
    });
  });

  const chartW = 6.4;
  s.addChart(pres.ChartType.bar, [{
    name: "制約数",
    labels: ["閾値証明のみ", "+ Version Policy", "+ 証明書を隠す"],
    values: [3829, 12570, 28596],
  }], {
    x: M, y: 3.4, w: chartW, h: 3.0,
    barDir: "col", barGapWidthPct: 55,
    chartColors: [IND_LT],
    showTitle: false, showLegend: false,
    showValue: true, dataLabelPosition: "outEnd",
    dataLabelColor: INDIGO, dataLabelFontFace: F, dataLabelFontSize: 12, dataLabelFontBold: true,
    catAxisLabelColor: "3A3F63", catAxisLabelFontFace: F, catAxisLabelFontSize: 11,
    valAxisLabelColor: MUTED, valAxisLabelFontFace: F, valAxisLabelFontSize: 10,
    valAxisMaxVal: 34000,
    valGridLine: { color: LILAC2, size: 1 },
    catGridLine: { style: "none" },
  });

  const tx = M + chartW + 0.45, tw = CW - chartW - 0.45;
  card(s, tx, 3.4, tw, 3.0, LILAC);
  s.addText("何に、いくら払ったか", {
    x: tx + 0.32, y: 3.68, w: tw - 0.64, h: 0.4, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 17, bold: true, color: INDIGO,
  });
  s.addText([
    { text: "3,829 / 17 ms — 公開証明書への閾値証明", options: { bullet: true, breakLine: true } },
    { text: "12,570 / 34 ms — Manifest Version Policy を足す", options: { bullet: true, breakLine: true } },
    { text: "28,596 / 55 ms — 証明書ごと隠す", options: { bullet: true } },
  ], {
    x: tx + 0.32, y: 4.2, w: tw - 0.64, h: 1.5, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 12.5, color: "3A3F63", lineSpacing: 19, paraSpaceAfter: 9,
  });
  s.addText("内訳は署名 2 本が 54%、Version Policy が 24%。", {
    x: tx + 0.32, y: 5.75, w: tw - 0.64, h: 0.5, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 11.5, italic: true, color: MUTED, lineSpacing: 17,
  });
  pageNum(s);
  s.addNotes("4:00-4:25 数字。制約が 2 段階で増えた推移を『プライバシーの値段』として語る。55 ms なら市場の効率を損なうレベルではない、と添える。");
}

// =======================================================================
// 12. LIMITS
// =======================================================================
{
  const s = slide();
  head(s, "10 ─ 限界", "暗号が守るのはプライバシーで、信頼ではない");

  const items = [
    ["信頼は Issuer Registry に依存する",
     "偽レビュー・Sybil・共謀は防げない。Gateway の検査はコストを上げるだけ。"],
    ["MPC は現構成では限定的",
     "隠せるのは Committee のノードからで、Gateway からではない。3 ノードは 1 プロセス内。"],
    ["残る経路は 1 つ — 現在の manifestCommitment は公開",
     "Policy が構成を指定する以上、ハッシュは出る。今あるのは「同じ構成のグループ内での匿名性」。"],
  ];
  const top = 1.9, rh = 1.15;
  items.forEach(([t, d], i) => {
    const y = top + i * (rh + 0.17);
    card(s, M, y, CW, rh, LILAC);
    badge(s, M + 0.32, y + (rh - 0.42) / 2, String(i + 1));
    s.addText(t, {
      x: M + 0.95, y: y + 0.16, w: CW - 1.3, h: 0.38, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 15, bold: true, color: INDIGO,
    });
    s.addText(d, {
      x: M + 0.95, y: y + 0.56, w: CW - 1.3, h: 0.55, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 12.5, color: "3A3F63", lineSpacing: 18,
    });
  });

  s.addShape(pres.ShapeType.roundRect, { x: M, y: 6.02, w: CW, h: 0.78, fill: { color: GREEN_L }, rectRadius: 0.08 });
  s.addText("次は Policy を「許可された Manifest 集合への包含」に変えて閉じる。その先は Gateway の不要化。", {
    x: M + 0.35, y: 6.02, w: CW - 0.7, h: 0.78, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 13, bold: true, color: GREEN, valign: "middle",
  });
  pageNum(s);
  s.addNotes("4:25-4:45 限界。ここが最後のスライドになるので、質疑の間もこの 1 枚が映り続ける。弱点としてではなく設計判断として言う。自分から先に出す。ここを誠実に出すと、質疑が Shamir・直接秘密分散・許可 Manifest 集合という先の話に進む。");
}

// =======================================================================
// 13. BACKUP DIVIDER
// =======================================================================
{
  const s = slide({ dark: true });
  s.addText("BACKUP", {
    x: M, y: 3.05, w: CW, h: 0.4, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 15, bold: true, charSpacing: 4, color: IND_LT, align: "center",
  });
  s.addText("質疑用のスライド", {
    x: M, y: 3.55, w: CW, h: 0.8, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 34, bold: true, color: WHITE, align: "center",
  });
  s.addText("構成の詳細　·　何が溜まるか　·　照会ではなく代行　·　照会先がない　·　比較表　·　なぜ ZK か　·　制約の内訳　·　信頼の前提　·　メンターの指摘　·　想定問答", {
    x: M, y: 4.45, w: CW, h: 0.4, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 14, color: MUTED, align: "center",
  });
  pageNum(s);
  s.addNotes("ここから先は本編では出さない。質疑で必要になったときだけ飛ぶ。");
}

// =======================================================================
// 14. BACKUP - ARCHITECTURE DETAIL
// =======================================================================
{
  const s = slide();
  head(s, "BACKUP", "構成の詳細 — ステークホルダーと技術スタック");

  const steps = [
    ["1", "Task Provider\n（取引先）", "仕事を依頼して評価を出した会社。結果に Receipt を発行する。デモでは Provider A・B・C。", "Ed25519 署名"],
    ["2", "Input Gateway", "署名・登録・重複・同一発行者・期限・範囲の 6 つを検査し、評価を分割する。", "3 者の加算的秘密分散"],
    ["3", "Reputation Committee", "3 ノードが部分和を出し、2-of-3 で証明書に署名。ノード数は回路の固定値。", "BabyJubJub 上の EdDSA"],
    ["4", "Agent", "agentSecret と Manifest を持ち、証明書を外に出さずに証明だけを作る。", "Groth16 / BN254（gnark）"],
    ["5", "Service（検証者）", "Policy と nonce を発行し、5 つの検査で受理。公開入力は自分で組み立て直す。", "Poseidon2 コミットメント"],
  ];
  const bw = 2.0, gap = (CW - bw * 5) / 4, top = 1.82, bh = 2.42;
  steps.forEach(([n, t, d, tech], i) => {
    const x = M + i * (bw + gap);
    const isAgent = i === 3;
    card(s, x, top, bw, bh, isAgent ? INDIGO : LILAC);
    const fg = isAgent ? WHITE : INDIGO, bgc = isAgent ? INDIGO : LILAC;
    const ix = x + 0.5, iy = top + 0.2, iz = 0.46;
    if (i === 0) iconBuilding(s, ix, iy, iz, fg, bgc);
    if (i === 1) iconFunnel(s, ix, iy, iz, fg);
    if (i === 2) iconNodes(s, ix, iy, iz, fg, GREEN);
    if (i === 3) robot(s, ix + 0.02, iy + 0.02, 0.29, { head: WHITE, part: LILAC2, eye: GREEN, mouth: INDIGO });
    if (i === 4) iconBuilding(s, ix, iy, iz, fg, bgc);
    badge(s, x + 1.08, top + 0.22, n, isAgent ? WHITE : INDIGO, isAgent ? INDIGO : WHITE);
    s.addText(t, {
      x: x + 0.12, y: top + 0.76, w: bw - 0.24, h: 0.46, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 12, bold: true, color: isAgent ? WHITE : INDIGO, align: "center",
    });
    s.addText(d, {
      x: x + 0.14, y: top + 1.24, w: bw - 0.28, h: 0.72, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 9.5, color: isAgent ? LILAC2 : "3A3F63", align: "center", lineSpacing: 14,
    });
    s.addText(tech, {
      x: x + 0.14, y: top + 2.0, w: bw - 0.28, h: 0.32, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 9, bold: true, color: isAgent ? GREEN : MUTED, align: "center",
    });
    if (i < 3) {
      s.addShape(pres.ShapeType.rightArrow, {
        x: x + bw + (gap - 0.4) / 2, y: top + 1.02, w: 0.4, h: 0.32, fill: { color: IND_LT },
      });
    }
    if (i === 3) {
      s.addShape(pres.ShapeType.leftArrow, {
        x: x + bw + (gap - 0.4) / 2, y: top + 0.82, w: 0.4, h: 0.28, fill: { color: MUTED },
      });
      s.addShape(pres.ShapeType.rightArrow, {
        x: x + bw + (gap - 0.4) / 2, y: top + 1.22, w: 0.4, h: 0.28, fill: { color: GREEN },
      });
    }
  });

  s.addShape(pres.ShapeType.roundRect, { x: M, y: 4.46, w: CW, h: 0.82, fill: { color: INDIGO }, rectRadius: 0.08, shadow: sh() });
  s.addText("① 署名付き Receipt　→　② 評価の share　→　③ 証明書と開示情報　→　④ Policy と nonce（Service → Agent）　→　⑤ 証明と公開入力 20 個", {
    x: M + 0.4, y: 4.46, w: CW - 0.8, h: 0.82, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 11.5, bold: true, color: WHITE, valign: "middle", align: "center",
  });

  s.addShape(pres.ShapeType.roundRect, { x: M, y: 5.45, w: CW, h: 1.1, fill: { color: LILAC }, rectRadius: 0.08 });
  s.addText([
    { text: "証明書は Agent で止まる。⑤ が運ぶのは Groth16 の証明（164 bytes）と公開入力 20 個だけで、証明書・合計点・件数・取引先は含まれない。", options: { fontSize: 12, bold: true, color: INDIGO, breakLine: true } },
    { text: "Go 1.25（外部サービス不要）　·　証明系 Groth16 / BN254（gnark）　·　回路内のハッシュとコミットメントは Poseidon2　·　Committee 署名は回路内で検証（チャレンジは MiMC）", options: { fontSize: 11, color: "3A3F63" } },
  ], {
    x: M + 0.4, y: 5.45, w: CW - 0.8, h: 1.1, isTextBox: true, margin: 0, valign: "middle", lineSpacing: 22,
  });
  pageNum(s);
  s.addNotes("メンター指摘①（ステークホルダーと技術スタックを明示した構成図が欲しい）への直接の答え。本編 6 枚目より詳しい版で、④ が Service → Agent の向きであることと、各層にどの技術を使っているかまで出している。");
}

// =======================================================================
// 15. BACKUP - NOTHING ACCUMULATES
// =======================================================================
{
  const s = slide();
  head(s, "BACKUP", "どこにも「評価表」は溜まらない");

  const hdr = (t) => ({ text: t, options: { fill: { color: INDIGO }, color: WHITE, bold: true, fontSize: 11.5, align: "left", valign: "middle", fontFace: F } });
  const k = (t) => ({ text: t, options: { fontSize: 12, bold: true, color: INDIGO, align: "left", valign: "middle", fontFace: F } });
  const c = (t) => ({ text: t, options: { fontSize: 11.5, color: "3A3F63", align: "left", valign: "middle", fontFace: F } });
  const yes = { text: "✓", options: { color: GREEN, bold: true, fontSize: 15, align: "center", valign: "middle", fontFace: F } };
  const no = { text: "✗", options: { color: CORAL, bold: true, fontSize: 15, align: "center", valign: "middle", fontFace: F } };
  const part = (t) => ({ text: t, options: { fontSize: 11, bold: true, color: MUTED, align: "center", valign: "middle", fontFace: F } });

  s.addTable([
    [hdr("どこに"), hdr("何が残るか"), hdr("誰が誰を評価したか"), hdr("点数")],
    [k("Receipt（現物）"), c("3 つ組すべて。Gateway を通ると破棄される"), yes, yes],
    [k("Input Gateway"), c("重複検出のキーだけ。値は空の構造体"), yes, no],
    [k("Committee ノード"), c("batchKey ごとの部分和が 1 つ"), no, no],
    [k("Agent"), c("証明書・合計点・その乱数"), no, part("合計だけ")],
    [k("Service（検証者）"), c("そのサービス専用の nullifier"), no, no],
  ], {
    x: M, y: 1.85, w: CW, colW: [2.5, 4.5, 2.2, 2.733],
    rowH: [0.55, 0.64, 0.64, 0.64, 0.64, 0.64],
    border: { type: "solid", color: WHITE, pt: 2 },
    fill: { color: LILAC }, fontFace: F,
  });

  s.addShape(pres.ShapeType.roundRect, { x: M, y: 5.8, w: CW, h: 0.72, fill: { color: INK }, rectRadius: 0.08, shadow: sh() });
  s.addText("issuerEpochKeys map[string]struct{}　←　値が空。点数を入れる場所そのものがない", {
    x: M + 0.3, y: 5.8, w: CW - 0.6, h: 0.72, isTextBox: true, margin: 0,
    fontFace: FM, fontSize: 13, bold: true, color: GREEN, valign: "middle", align: "center",
  });
  pageNum(s);
  s.addNotes("「評価が溜まっていくんですよね？」と言われたときの 1 枚。溜まるのは『A 社が この封筒を この期間に この領域で 評価した』という二部グラフだけで、重み（★の値）はどこにも残らない。しかもそれは重複検出の副産物。個別の ★5・★4・★5 は Committee が足し込んだ時点で区別がつかなくなり、残るのは合計 14 だけ。MVP では Gateway も Committee も永続化していない（enroll のたびに作り直し、鍵は捨てる）。");
}

// =======================================================================
// 16. BACKUP - PROXY NOT LOOKUP
// =======================================================================
{
  const s = slide();
  head(s, "BACKUP", "照会ではなく、代行して証明する");

  const box = (x, y, w, h, label, fill, color, line) => {
    s.addShape(pres.ShapeType.roundRect, Object.assign(
      { x, y, w, h, fill: { color: fill }, rectRadius: 0.06 },
      line ? { line: { color: line, width: 2 } } : {}));
    s.addText(label, {
      x, y, w, h, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 12.5, bold: true, color, align: "center", valign: "middle",
    });
  };

  // ---- ✗ 照会モデル ----------------------------------------------------
  card(s, M, 1.75, CW, 1.5, CORAL_L);
  s.addText("✗　照会モデル（信用情報機関）", {
    x: M + 0.35, y: 1.82, w: 4.6, h: 0.32, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 13, bold: true, color: CORAL,
  });
  box(1.15, 2.54, 2.3, 0.6, "予約サービス", INDIGO, WHITE);
  box(5.35, 2.54, 2.3, 0.6, "中央の台帳", CORAL, WHITE);
  box(9.55, 2.54, 2.3, 0.6, "予約サービス", INDIGO, WHITE);
  [[3.45, "「条件を満たす？」"], [7.65, "「満たします」"]].forEach(([gx, t]) => {
    s.addText(t, {
      x: gx, y: 2.22, w: 1.9, h: 0.26, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 9.5, bold: true, color: CORAL, align: "center",
    });
    s.addShape(pres.ShapeType.rightArrow, { x: gx + 0.7, y: 2.68, w: 0.5, h: 0.32, fill: { color: CORAL } });
  });

  // ---- ✓ 証明モデル ----------------------------------------------------
  card(s, M, 3.42, CW, 2.45, GREEN_L);
  s.addText("✓　証明モデル（zkAgent Passport）", {
    x: M + 0.35, y: 3.49, w: 5.2, h: 0.32, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 13, bold: true, color: GREEN,
  });
  box(1.4, 4.22, 2.7, 0.62, "予約サービス", INDIGO, WHITE);
  box(8.5, 4.22, 2.7, 0.62, "Agent", "F8F9FD", INDIGO, INDIGO);
  s.addText("①「私の条件はこれです」Policy と nonce", {
    x: 4.3, y: 3.90, w: 4.0, h: 0.26, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 10, bold: true, color: INDIGO, align: "center",
  });
  s.addShape(pres.ShapeType.rightArrow, { x: 6.0, y: 4.28, w: 0.6, h: 0.24, fill: { color: IND_LT } });
  s.addShape(pres.ShapeType.leftArrow, { x: 6.0, y: 4.62, w: 0.6, h: 0.24, fill: { color: GREEN } });
  s.addText("③「調べました。これがその証明です」164 bytes", {
    x: 4.2, y: 4.94, w: 4.2, h: 0.26, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 10, bold: true, color: GREEN, align: "center",
  });
  s.addText("④ 検算するだけ。誰にも聞かない", {
    x: 1.4, y: 4.94, w: 2.7, h: 0.46, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 10.5, bold: true, color: INDIGO, align: "center", valign: "middle",
  });
  s.addText("② 自分で調べる（回路を実行）", {
    x: 8.5, y: 4.94, w: 2.7, h: 0.46, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 10.5, bold: true, color: INDIGO, align: "center", valign: "middle",
  });

  // ---- 落ち -------------------------------------------------------------
  s.addShape(pres.ShapeType.roundRect, { x: M, y: 6.02, w: CW, h: 0.7, fill: { color: INDIGO }, rectRadius: 0.08, shadow: sh() });
  s.addText("サービスがやるはずだった照会を、Agent が自分の手元で済ませて、済ませたことを証明する", {
    x: M + 0.4, y: 6.02, w: CW - 0.8, h: 0.7, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 15, bold: true, color: WHITE, valign: "middle", align: "center",
  });
  pageNum(s);
  s.addNotes("上の図は「あなたが思い浮かべている形」、下が実際の形。違いは矢印の向きと本数。照会モデルでは中央に問い合わせが飛び、答えが返る。証明モデルでは、サービスは条件を出すだけで、調べるのは Agent 自身。調べた結果ではなく『調べて通った』ことを 164 バイトの証明にして返す。サービスはそれを検算するだけで、Committee にも Gateway にも Provider にも一度も聞かない。一言でいうと、サービスがやるはずだった照会を Agent が代行して、代行したことを証明している。");
}

// =======================================================================
// 17. BACKUP - NO LOOKUP
// =======================================================================
{
  const s = slide();
  head(s, "BACKUP", "照会先がない — 信用情報機関ではなく、パスポート");

  const cw2 = (CW - 0.45) / 2, top = 1.85, ch = 3.2;

  card(s, M, top, cw2, ch, CORAL_L);
  s.addText("✗　照会モデル（信用情報機関）", {
    x: M + 0.35, y: top + 0.3, w: cw2 - 0.7, h: 0.42, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 16, bold: true, color: CORAL,
  });
  s.addText([
    { text: "サービスが中央に「この Agent は条件を満たすか」と聞く", options: { bullet: true, breakLine: true } },
    { text: "中央が全履歴を持つ", options: { bullet: true, breakLine: true } },
    { text: "誰がどのサービスにいつ来たかも中央に残る", options: { bullet: true, breakLine: true } },
    { text: "可用性も中央に依存する", options: { bullet: true } },
  ], {
    x: M + 0.35, y: top + 0.88, w: cw2 - 0.7, h: 2.1, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 13, color: "5A2418", lineSpacing: 21, paraSpaceAfter: 9,
  });

  card(s, M + cw2 + 0.45, top, cw2, ch, GREEN_L);
  s.addText("✓　証明モデル（zkAgent Passport）", {
    x: M + cw2 + 0.8, y: top + 0.3, w: cw2 - 0.7, h: 0.42, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 16, bold: true, color: GREEN,
  });
  s.addText([
    { text: "サービスは条件（Policy と nonce）を出すだけ", options: { bullet: true, breakLine: true } },
    { text: "Agent が自分の手元で検査し、証明を作る", options: { bullet: true, breakLine: true } },
    { text: "サービスは証明を検算するだけ。誰にも聞かない", options: { bullet: true, breakLine: true } },
    { text: "証明書を出したあと、Committee は二度と登場しない", options: { bullet: true } },
  ], {
    x: M + cw2 + 0.8, y: top + 0.88, w: cw2 - 0.7, h: 2.1, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 13, color: "23483C", lineSpacing: 21, paraSpaceAfter: 9,
  });

  s.addShape(pres.ShapeType.roundRect, { x: M, y: 5.25, w: CW, h: 0.72, fill: { color: INK }, rectRadius: 0.08, shadow: sh() });
  s.addText("verifier の import は errors と fmt だけ　←　net/http も database/sql もない", {
    x: M + 0.3, y: 5.25, w: CW - 0.6, h: 0.72, isTextBox: true, margin: 0,
    fontFace: FM, fontSize: 13, bold: true, color: GREEN, valign: "middle", align: "center",
  });

  note(s, 6.15, "そもそもサービスは passportCommitment を知らない。見えるのは自分専用の nullifier だけなので、照会しようにもキーがない。");
  pageNum(s);
  s.addNotes("「サービスが zkPass に問い合わせて答えをもらうんですよね？」と言われたときの 1 枚。問い合わせる相手が存在しない、というのが答え。サービスの 5 つの検査は全部ローカル処理で、Committee にも Gateway にも Provider にも一度も通信しない。照会先を置くと、その相手が『どの Agent がどのサービスにいつ来たか』を全部握る監視者になる。それを避けるのが ZK を使う理由の 1 つ。普通のパスポートとの違いは、提示しても中身が見えず、審査官ごとに別の整理番号（nullifier）になること。");
}

// =======================================================================
// 18. COMPARISON TABLE
// =======================================================================
{
  const s = slide();
  head(s, "BACKUP", "既存のやり方と、何が違うのか");

  const hdr = (t) => ({ text: t, options: { fill: { color: INDIGO }, color: WHITE, bold: true, fontSize: 12, align: "center", valign: "middle", fontFace: F } });
  const yes = { text: "✓", options: { color: GREEN, bold: true, fontSize: 17, align: "center", valign: "middle", fontFace: F } };
  const no  = { text: "✗", options: { color: CORAL, bold: true, fontSize: 17, align: "center", valign: "middle", fontFace: F } };
  const txt = (t, o = {}) => ({ text: t, options: Object.assign({ fontSize: 12, color: "3A3F63", align: "center", valign: "middle", fontFace: F }, o) });
  const row0 = (t, o = {}) => ({ text: t, options: Object.assign({ fontSize: 13, bold: true, color: INDIGO, align: "left", valign: "middle", fontFace: F }, o) });

  const rows = [
    [hdr("方式"), hdr("偽装耐性"), hdr("取引先の秘匿"), hdr("合計点の秘匿"), hdr("構成変更の扱い"), hdr("サービスごとの条件")],
    [row0("星評価（プラットフォーム）"), no, no, no, txt("引き継がれる"), txt("—")],
    [row0("署名付きスコアの公開"), yes, no, no, txt("発行元に再依頼"), txt("条件ごとに再発行")],
    [row0("zkAgent Passport", { fill: { color: LILAC2 } }),
      Object.assign({}, yes, { options: Object.assign({}, yes.options, { fill: { color: LILAC2 } }) }),
      Object.assign({}, yes, { options: Object.assign({}, yes.options, { fill: { color: LILAC2 } }) }),
      Object.assign({}, yes, { options: Object.assign({}, yes.options, { fill: { color: LILAC2 } }) }),
      txt("Policy が範囲を決める", { fill: { color: LILAC2 }, bold: true }),
      txt("証明書 1 通で対応", { fill: { color: LILAC2 }, bold: true })],
  ];

  s.addTable(rows, {
    x: M, y: 2.0, w: CW, colW: [3.1, 1.5, 1.7, 1.7, 2.1, 1.833],
    rowH: [0.66, 0.92, 0.92, 1.02],
    border: { type: "solid", color: WHITE, pt: 2 },
    fill: { color: LILAC },
    fontFace: F,
  });

  note(s, 5.95, "解いているのは「偽装をなくすこと」ではなく、偽装耐性を保ったまま何も見せないこと。");
  pageNum(s);
  s.addNotes("本編からは外した 1 枚。「他の方式でよいのでは」と聞かれたら出す。署名付きでスコアを公開すれば偽装は防げる。しかし取引先も合計点も見えるし、条件が変わるたび発行元に頼み直すことになる。zkAgent Passport は、この 3 列を同時に埋めにいく。");
}

// =======================================================================
// 19. WHY ZK
// =======================================================================
{
  const s = slide();
  head(s, "BACKUP", "なぜ Committee の署名ではなく、ゼロ知識証明なのか");

  const cw2 = (CW - 0.45) / 2, top = 1.95, ch = 3.45;
  card(s, M, top, cw2, ch, CORAL_L);
  s.addText("Committee が「12 点以上」と署名したら？", {
    x: M + 0.35, y: top + 0.32, w: cw2 - 0.7, h: 0.45, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 16, bold: true, color: CORAL,
  });
  s.addText([
    { text: "閾値も Version Policy も、サービスごとに違う", options: { bullet: true, breakLine: true } },
    { text: "新しい条件が出るたびに Committee へ依頼し直すことになる", options: { bullet: true, breakLine: true } },
    { text: "依頼の履歴そのものが、満たしている閾値を漏らす", options: { bullet: true } },
  ], {
    x: M + 0.35, y: top + 0.95, w: cw2 - 0.7, h: 2.0, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 14, color: "5A2418", lineSpacing: 24, paraSpaceAfter: 10,
  });

  card(s, M + cw2 + 0.45, top, cw2, ch, GREEN_L);
  s.addText("証明にすると", {
    x: M + cw2 + 0.8, y: top + 0.32, w: cw2 - 0.7, h: 0.45, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 16, bold: true, color: GREEN,
  });
  s.addText([
    { text: "証明書 1 通で、どんな Policy にも Committee 抜きで答えられる", options: { bullet: true, breakLine: true } },
    { text: "証明は verifierId・nonce・policyHash・期限に束縛される", options: { bullet: true, breakLine: true } },
    { text: "他サービスへの転用も、別条件への転用も、再送も落ちる", options: { bullet: true } },
  ], {
    x: M + cw2 + 0.8, y: top + 0.95, w: cw2 - 0.7, h: 2.0, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 14, color: "23483C", lineSpacing: 24, paraSpaceAfter: 10,
  });

  note(s, 5.85, "「条件がサービスごとに違う」ことが、ZK を必然にしている。");
  pageNum(s);
  s.addNotes("質疑で必ず来る問い。「Committee が 12 点以上と署名すれば済むのでは」と聞かれたらこの 1 枚を出す。");
}

// =======================================================================
// 20. BACKUP - CONSTRAINT BREAKDOWN
// =======================================================================
{
  const s = slide();
  head(s, "BACKUP", "制約 28,596 の内訳");

  s.addChart(pres.ChartType.bar, [{
    name: "制約数",
    labels: [
      "鍵セットの選択と署名者の相異",
      "32bit の比較（score・件数・期限）",
      "コミットメントの開示",
      "Policy のハッシュ（8 入力）",
      "Manifest の開示（4 入力 × 2）",
      "証明書のハッシュ（10 入力）",
      "Manifest Version Policy",
      "Committee の署名（EdDSA 2 本）",
    ],
    values: [22, 297, 1119, 1489, 1490, 1861, 6776, 15538],
  }], {
    x: M, y: 1.9, w: 8.5, h: 4.6,
    barDir: "bar", barGapWidthPct: 45,
    chartColors: [IND_LT],
    showTitle: false, showLegend: false,
    showValue: true, dataLabelPosition: "outEnd",
    dataLabelColor: INDIGO, dataLabelFontFace: F, dataLabelFontSize: 11, dataLabelFontBold: true,
    catAxisLabelColor: "3A3F63", catAxisLabelFontFace: F, catAxisLabelFontSize: 11,
    valAxisLabelColor: MUTED, valAxisLabelFontFace: F, valAxisLabelFontSize: 10,
    valAxisMaxVal: 18000,
    valGridLine: { color: LILAC2, size: 1 },
    catGridLine: { style: "none" },
  });

  const tx = M + 8.5 + 0.45, tw = CW - 8.5 - 0.45;
  card(s, tx, 1.9, tw, 4.6, LILAC);
  s.addText("証明書を隠す代償", {
    x: tx + 0.3, y: 2.18, w: tw - 0.6, h: 0.4, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 16, bold: true, color: INDIGO,
  });
  s.addText([
    { text: "Committee 署名の回路内検証だけで 54%。証明書をサービスに渡さないための本体。", options: { bullet: true, breakLine: true } },
    { text: "Version Policy が 24%。4 項目それぞれに leaf と深さ 4 の Merkle 経路が要る。", options: { bullet: true, breakLine: true } },
    { text: "残りはハッシュと開示。範囲比較は 297 制約しかない。", options: { bullet: true, breakLine: true } },
    { text: "公開入力は 20 個。Policy 9・challenge 3・鍵セット ID・公開鍵 3 本（各 2 座標）・nullifier。", options: { bullet: true } },
  ], {
    x: tx + 0.3, y: 2.7, w: tw - 0.6, h: 3.5, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 12, color: "3A3F63", lineSpacing: 18, paraSpaceAfter: 10,
  });
  pageNum(s);
  s.addNotes("『制約数の内訳は？』に即答するための 1 枚。");
}

// =======================================================================
// 21. BACKUP - TRUST ASSUMPTIONS
// =======================================================================
{
  const s = slide();
  head(s, "BACKUP", "信頼の前提と、対象外にしたもの");

  const hdr = (t) => ({ text: t, options: { fill: { color: INDIGO }, color: WHITE, bold: true, fontSize: 12, align: "left", valign: "middle", fontFace: F } });
  const c = (t, o = {}) => ({ text: t, options: Object.assign({ fontSize: 12, color: "3A3F63", align: "left", valign: "middle", fontFace: F }, o) });
  const k = (t) => ({ text: t, options: { fontSize: 12.5, bold: true, color: INDIGO, align: "left", valign: "middle", fontFace: F } });

  const rows = [
    [hdr("参加者 / 項目"), hdr("何を前提にしているか"), hdr("破られたらどうなるか")],
    [k("Issuer Registry"), c("登録済み Provider は正しい評価を出す"), c("偽レビュー・Sybil・共謀は防げない。Gateway の検査はコストを上げるだけ")],
    [k("Input Gateway"), c("正しく 6 つの検査を行う。平文の評価を見る"), c("Gateway が嘘の評価を通せる。Provider → Committee 直接分散で解消できる")],
    [k("Reputation Committee"), c("semi-honest。3 ノードは 1 プロセス内のシミュレーション"), c("2 ノード署名は単独発行を防ぐだけ。悪意ある 2 ノードには無力")],
    [k("Manifest"), c("束縛するのは宣言であって、実行ではない"), c("宣言どおりに動いた保証はない。Remote Attestation / TEE と組み合わせる領域")],
    [k("Groth16 setup"), c("開発専用の単一者セットアップ"), c("本番には MPC ceremony が要る。失効機構と真の閾値署名も未実装")],
  ];

  s.addTable(rows, {
    x: M, y: 1.9, w: CW, colW: [2.7, 4.3, 4.933],
    rowH: [0.5, 0.72, 0.72, 0.72, 0.72, 0.72],
    border: { type: "solid", color: WHITE, pt: 2 },
    fill: { color: LILAC },
    fontFace: F,
  });

  note(s, 6.1, "暗号が守っているのはプライバシーであって、信頼そのものではない。");
  pageNum(s);
  s.addNotes("信頼前提を聞かれたらこの 1 枚。自分から本編で 1 行触れてあるので、ここは詳細版。");
}

// =======================================================================
// 22. BACKUP - MENTOR FEEDBACK
// =======================================================================
{
  const s = slide();
  head(s, "BACKUP", "メンターからの指摘と、その回答");

  s.addText("zk-tokyo/advanced-cryptography-2026 Issue #124（SeiyaKobayashi さん、2026-08-21）", {
    x: M, y: 1.76, w: CW, h: 0.3, isTextBox: true, margin: 0,
    fontFace: F, fontSize: 11, color: MUTED,
  });

  const items = [
    ["ステークホルダーと技術スタックを明示した構成図が欲しい（発表にも使える）",
     "Issue 本文と README に Mermaid の構成図を追加した。本編 6 枚目と、直前のバックアップ「構成の詳細」がその図に当たる。"],
    ["Agent は Lambda のような単発実行が主流になる。その場合の「Agent の存在単位」は何か",
     "実行プロセスではなく「agentSecret の保持 × Manifest の宣言」。同じ鍵と同じ Manifest なら単発実行でも同一 Agent として実績が積まれる。cmd/agent prove は 起動 → 環境変数から鍵を読む → 証明 → 終了 で、nonce の状態は Service 側が持つ。常時稼働は前提にしない。"],
    ["ZK + MPC の計算量ボトルネックを定量評価としてスコープに入れるとよい",
     "Scope に Performance Evaluation を追加し、go run ./cmd/bench で実測した。制約 28,596（Committee 署名 54% / Version Policy 24%）、証明 55 ms、検証 1 ms 未満、164 bytes。MPC は加算的秘密分散なので集計は軽微で、ボトルネックは証明生成側にある。"],
  ];
  const top = 2.15, rh = 1.38;
  items.forEach(([q, a], i) => {
    const y = top + i * (rh + 0.15);
    card(s, M, y, CW, rh, LILAC);
    badge(s, M + 0.3, y + 0.2, String(i + 1));
    s.addText(q, {
      x: M + 0.92, y: y + 0.16, w: CW - 1.25, h: 0.38, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 13.5, bold: true, color: INDIGO, valign: "middle",
    });
    s.addText(a, {
      x: M + 0.92, y: y + 0.58, w: CW - 1.25, h: 0.68, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 11.5, color: "3A3F63", lineSpacing: 17,
    });
  });
  pageNum(s);
  s.addNotes("メンター（SeiyaKobayashi さん）から 2026-08-21 に来た 3 点。3 つとも実装と計測で答えが出ている。Issue への返信自体はまだ投稿していないので、聞かれたらそのまま言う。");
}

// =======================================================================
// 23. BACKUP - Q&A
// =======================================================================
{
  const s = slide();
  head(s, "BACKUP", "想定問答");

  const qa = [
    ["Gateway が平文を見るのに MPC は要るのか", "Committee のノードから個別評価を隠す防御線。将来 Provider が直接秘密分散する構成への布石で、現構成では限定的だと認める。"],
    ["Lambda のような単発実行で Agent の単位は？", "実行プロセスではなく agentSecret の保持 × Manifest の宣言。cmd/agent prove は起動 → 証明 → 終了。nonce は Service 側が持つ。"],
    ["Sybil / Review Farming は防げるか", "防げない。Issuer Registry への信頼に依存する。Gateway の検査は同一 Provider の 2 件目などを弾くが、コストを上げるだけ。"],
    ["高スコアなら公開したいのでは", "秘匿の主目的は合計点そのものより、取引先の名前と個別の低評価。B2B では実需がある。"],
    ["実行時に同じモデルが使われている保証は", "無い。Manifest は宣言への束縛で、Remote Attestation は対象外。TEE とは競合ではなく補完関係。"],
  ];
  const top = 1.9, rh = 0.87;
  qa.forEach(([q, a], i) => {
    const y = top + i * (rh + 0.15);
    card(s, M, y, CW, rh, LILAC);
    badge(s, M + 0.28, y + (rh - 0.42) / 2, "Q");
    s.addText(q, {
      x: M + 0.9, y: y + 0.11, w: CW - 1.2, h: 0.32, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 13, bold: true, color: INDIGO, valign: "middle",
    });
    s.addText(a, {
      x: M + 0.9, y: y + 0.43, w: CW - 1.2, h: 0.36, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 11.5, color: "3A3F63", valign: "middle", lineSpacing: 16,
    });
  });
  pageNum(s);
  s.addNotes("2 分の質疑はこの 5 つでほぼ埋まる。声に出して 1 回ずつ答える練習をしておく。");
}

// =======================================================================
// 24. PROBLEM (無効化: 場面スライドに統合)
// =======================================================================
/*  2026-09-12 に「01 ─ 場面」へ統合した。分けて話したくなったらこのコメントを外し、
    new_order に "PROBLEM (無効化: 場面スライドに統合)" を戻す。

{
  const s = slide();
  head(s, "02 ─ 問題", "しかし、D 社にはそれを確かめる手段がない");

  s.addShape(pres.ShapeType.roundRect, { x: M, y: 1.9, w: CW, h: 0.98, fill: { color: INDIGO }, rectRadius: 0.08, shadow: sh() });
  s.addText([
    { text: "Agent「A・B・C 社から 5・4・5 の評価をもらっています」", options: { fontSize: 17, bold: true, color: WHITE, breakLine: true } },
    { text: "D 社には、その数字が本当かどうかを確かめる方法がない", options: { fontSize: 12.5, color: LILAC2 } },
  ], {
    x: M + 0.4, y: 1.9, w: CW - 0.8, h: 0.98, isTextBox: true, margin: 0, valign: "middle", lineSpacing: 25,
  });

  const items = [
    ["1", "偽装できる", "星評価は自己申告と偽レビューで作れる。誰が出した数字なのかを確かめる術がない。"],
    ["2", "見せると全部漏れる", "実績を示すために履歴を渡すと、取引先の名前も個別の低評価も一緒に渡ることになる。"],
  ];
  const cw = (CW - 0.45) / 2, top = 3.18, ch = 2.3;
  items.forEach(([n, t, d], i) => {
    const x = M + i * (cw + 0.45);
    card(s, x, top, cw, ch);
    badge(s, x + 0.34, top + 0.32, n);
    s.addText(t, {
      x: x + 0.34, y: top + 0.94, w: cw - 0.68, h: 0.45, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 18, bold: true, color: INDIGO,
    });
    s.addText(d, {
      x: x + 0.34, y: top + 1.48, w: cw - 0.68, h: 0.7, isTextBox: true, margin: 0,
      fontFace: F, fontSize: 13.5, color: "3A3F63", lineSpacing: 22,
    });
  });

  note(s, 5.82, "自分で「信頼できます」と言うだけでは検証できない。かといって全部渡すと、A・B・C 社との取引が D 社に広がる。");
  pageNum(s);
  s.addNotes("0:35-0:55 問題①。D 社の立場で、Agent の自己申告を確かめる手段がないという話。星評価には 2 つの壊れ方がある。偽装できること、そして見せると全部漏れること。ここまでは人間の評判システムにもある問題だと言って、次で AI 固有の問題に進む。");
}
*/

pres.writeFile({ fileName: process.argv[2] || "zk-agent-passport.pptx" })
  .then((f) => console.log("wrote", f));
