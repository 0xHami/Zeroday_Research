const { chromium } = require('playwright');
(async () => {
  const url = process.env.TARGET_URL;
  const marker = process.env.MARKER;
  const browser = await chromium.launch();
  const page = await browser.newPage();
  let dialogFired = false;
  page.on('dialog', async d => { dialogFired = true; await d.dismiss(); });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForTimeout(800);
  const xss1 = await page.evaluate(m => window['__xss_'+m] || null, marker);
  const xss2 = await page.evaluate(m => window['__xss2_'+m] || null, marker);
  try { await page.screenshot({ path: '/work/exploits/VULN-004/evidence/xss_fired.png' }); } catch(e){}
  console.log('img.onerror executed (window.__xss_'+marker+') =', xss1);
  console.log('<script> executed (window.__xss2_'+marker+') =', xss2);
  console.log('dialog fired =', dialogFired);
  await browser.close();
  if (xss1 === 1 || xss2 === 1) { console.log('[OK] stored XSS EXECUTED in a real browser'); process.exit(0); }
  else { console.log('[FAIL] payload present but did not execute'); process.exit(1); }
})().catch(e => { console.error('error', e); process.exit(2); });
