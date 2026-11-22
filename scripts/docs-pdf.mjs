// Generuje PDF-y dokumentacji: docs/*.md → docs/pdf/*.pdf
// Wymaga: pandoc oraz Node.js z pakietem playwright (Chromium).
//   node scripts/docs-pdf.mjs
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, writeFileSync, rmSync } from "node:fs";
import { join, resolve, basename } from "node:path";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const root = resolve(import.meta.dirname, "..");
const docs = join(root, "docs");
const out = join(docs, "pdf");
const tmp = join(out, ".tmp");
mkdirSync(tmp, { recursive: true });

const logo = pathToFileURL(join(docs, "img", "logo-mark.png")).href;
const imgBase = pathToFileURL(join(docs, "img")).href;

const css = `
@page { size: A4; margin: 16mm 14mm 18mm 14mm; }
:root { --accent: #1f5fae; --line: #d7dde5; --soft: #f3f6fa; }
* { box-sizing: border-box; }
body { font-family: "DejaVu Sans", "Liberation Sans", Arial, sans-serif; font-size: 9.6pt;
       line-height: 1.45; color: #1b2430; margin: 0; }
header.doc { display: flex; align-items: center; gap: 10px; border-bottom: 2px solid var(--accent);
             padding-bottom: 6px; margin-bottom: 10px; }
header.doc img { width: 30px; }
header.doc span { color: #66717f; font-size: 8.5pt; margin-left: auto; }
h1 { font-size: 17pt; margin: 0; color: var(--accent); }
h2 { font-size: 12.5pt; margin: 16px 0 6px; padding-bottom: 2px; border-bottom: 1px solid var(--line);
     break-after: avoid; }
h3 { font-size: 10.5pt; margin: 12px 0 4px; break-after: avoid; }
p, ul, ol { margin: 4px 0 8px; }
li { margin: 2px 0; }
table { border-collapse: collapse; width: 100%; margin: 6px 0 10px; font-size: 8.6pt; break-inside: auto; }
tr { break-inside: avoid; }
th { background: var(--soft); text-align: left; font-weight: 600; }
th, td { border: 1px solid var(--line); padding: 3px 6px; vertical-align: top; }
code { font-family: "DejaVu Sans Mono", "Liberation Mono", monospace; font-size: 8.2pt;
       background: var(--soft); padding: 0 3px; border-radius: 3px; overflow-wrap: anywhere; }
pre { background: var(--soft); border: 1px solid var(--line); border-radius: 4px; padding: 6px 8px;
      white-space: pre-wrap; overflow-wrap: anywhere; break-inside: avoid; margin: 4px 0 10px; }
pre code { background: none; padding: 0; font-size: 7.9pt; }
a { color: var(--accent); text-decoration: none; }
blockquote { margin: 6px 0; padding: 4px 10px; border-left: 3px solid var(--accent); background: var(--soft); }
section.slide { break-after: page; height: 210mm; padding: 11mm 16mm 9mm; display: flex; flex-direction: column;
                justify-content: center; font-size: 17pt; position: relative; overflow: hidden;
                background:
                  radial-gradient(ellipse 60% 55% at 8% 0%, rgba(31,95,174,.22), transparent 70%),
                  radial-gradient(ellipse 55% 60% at 100% 100%, rgba(56,189,248,.22), transparent 70%),
                  radial-gradient(ellipse 40% 40% at 85% 10%, rgba(129,140,248,.14), transparent 70%),
                  linear-gradient(160deg, #f8fbff 0%, #eef4fb 100%); }
section.slide h1 { font-size: 36pt; }
section.slide h2 { font-size: 24pt; border: none; color: var(--accent); margin: 0 0 2mm; }
section.slide p { margin: 0 0 3mm; color: #3a4656; font-size: 13.5pt; }
section.slide code { font-size: 14pt; }
section.slide li { margin: 3mm 0; }
section.slide img.logo { max-height: 55mm; align-self: flex-start; filter: drop-shadow(0 0 18px rgba(56,189,248,.45)); }
section.slide p > img:not(.logo) { display: block; width: 100%; max-height: 150mm; object-fit: contain; object-position: top center;
                margin: 1mm auto 0; border-radius: 6px; border: 1px solid #d0dbea;
                box-shadow: 0 0 0 1px rgba(31,95,174,.06), 0 10px 40px rgba(31,95,174,.28), 0 0 70px rgba(56,189,248,.25); }
section.slide:last-child { break-after: auto; }
p > img { display: block; max-width: 100%; max-height: 225mm; margin: 0 auto; border: 1px solid var(--line); border-radius: 4px; break-inside: avoid; }
body.zrzuty-ekranu h2 { break-before: page; border: none; }
body.zrzuty-ekranu h2:first-of-type { break-before: auto; }
section.slide:last-child { break-after: auto; }
`;

const titles = {
  uruchomienie: "Instrukcja uruchomienia",
  architektura: "Architektura",
  cli: "Polecenia CLI",
  "analiza-skutecznosci": "Skuteczność na laboratorium",
  "bezpieczenstwo-skanera": "Bezpieczeństwo skanera",
  "klasyfikacja-danych": "Klasyfikacja danych",
  "testy-reczne": "Testy ręczne",
  prezentacja: "Prezentacja",
  hacknation: "Sprawdzanie wymagań w panelu WWW",
  "hacknation-techniczny": "Spełnienie wymagań - wersja techniczna",
  "zrzuty-ekranu": "Zrzuty ekranu",
};

function pandoc(markdown) {
  return execFileSync("pandoc", ["-f", "gfm", "-t", "html5", "--no-highlight"], {
    input: markdown,
    encoding: "utf8",
  });
}

function render(name) {
  const source = name === "hacknation" ? join(root, "hacknation.md") : join(docs, `${name}.md`);
  let md = readFileSync(source, "utf8");
  md = md.replace(/<img[^>]*>\s*/g, "").replace(/<\/?p[^>]*>\s*/g, "");
  if (name === "prezentacja") {
    md = md.replace(/^---\n[\s\S]*?\n---\n/, "");
    const slides = md.split(/\n---\n/).map((s) =>
      s
        .replace(/!\[[^\]]*\]\(img\/logo[^)]*\)/g, `<img class="logo" src="${logo}">`)
        .replace(/\]\(img\//g, `](${imgBase}/`),
    );
    return slides.map((s) => `<section class="slide">${pandoc(s)}</section>`).join("\n");
  }
  md = md.replace(/\]\(img\//g, `](${imgBase}/`);
  // Pierwszy nagłówek trafia do nagłówka dokumentu.
  const h1 = md.match(/^# (.+)$/m);
  md = md.replace(/^# .+$/m, "");
  const title = h1 ? pandoc(`# ${h1[1]}`).replace(/<h1[^>]*>|<\/h1>/g, "") : name;
  return `<header class="doc"><img src="${logo}"><h1>${title}</h1><span>DScan</span></header>${pandoc(md)}`;
}

const names = readdirSync(docs)
  .filter((f) => f.endsWith(".md"))
  .map((f) => basename(f, ".md"))
  .concat("hacknation");

const browser = await chromium.launch();
const page = await browser.newPage();
for (const name of names) {
  const html = `<!doctype html><html lang="pl"><head><meta charset="utf-8">
<title>DScan - ${titles[name] ?? name}</title><style>${css}${name === "prezentacja" ? "@page { size: A4 landscape; margin: 0; }" : ""}</style></head><body class="${name}">${render(name)}</body></html>`;
  const file = join(tmp, `${name}.html`);
  writeFileSync(file, html);
  await page.goto(pathToFileURL(file).href, { waitUntil: "load" });
  await page.pdf({
    path: join(out, `${name}.pdf`),
    preferCSSPageSize: true,
    printBackground: true,
    displayHeaderFooter: name !== "prezentacja",
    headerTemplate: "<span></span>",
    footerTemplate: `<div style="font-size:7pt;color:#8a94a3;width:100%;text-align:center;">
      DScan - ${titles[name] ?? name} · <span class="pageNumber"></span>/<span class="totalPages"></span></div>`,
  });
  console.log(`docs/pdf/${name}.pdf`);
}
await browser.close();
rmSync(tmp, { recursive: true, force: true });
