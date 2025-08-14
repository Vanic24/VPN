const puppeteer = require('puppeteer');
const fs = require('fs');

(async () => {
  const url = process.env.IGDUX_EDIT_URL;
  if (!url) { console.error('Missing IGDUX_EDIT_URL secret'); process.exit(1); }

  const content = fs.readFileSync('9PB', 'utf8');
  const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox'] });
  const page = await browser.newPage();

  await page.setExtraHTTPHeaders({ 'Accept': '*/*','Accept-Language': 'en-US,en;q=0.9' });

  console.log('🌐 Opening igdux editor...');
  await page.goto(url, { waitUntil: 'networkidle2', timeout: 60000 });

  const selector = 'textarea, [contenteditable="true"], #editor, #app textarea';
  await page.waitForSelector(selector, { timeout: 30000 });

  const isContentEditable = await page.$eval(selector, el => el.getAttribute && el.getAttribute('contenteditable') === 'true');

  if (isContentEditable) {
    await page.$eval(selector, (el, txt) => { el.innerText = txt; }, content);
  } else {
    await page.$eval(selector, (el, txt) => { el.value = txt; el.dispatchEvent(new Event('input', { bubbles: true })); }, content);
  }

  console.log('💾 Attempting to save...');

  async function tryXPathClick(xpath) {
    const handles = await page.$x(xpath);
    if (handles.length > 0) { await handles[0].click(); return true; }
    return false;
  }

  let saved = false;
  const attempts = [
    "//button[contains(., 'Save')]",
    "//button[contains(., '保存')]",
    "//button[contains(., 'submit')]",
    "//input[@type='submit']",
    "//button[@type='submit']",
    "//button[contains(@class,'save')]"
  ];

  for (const xp of attempts) {
    if (await tryXPathClick(xp)) { saved = true; break; }
  }

  if (!saved) {
    const key = process.platform === 'darwin' ? 'Meta' : 'Control';
    await page.keyboard.down(key);
    await page.keyboard.press('KeyS');
    await page.keyboard.up(key);
  }

  await page.waitForTimeout(3000);
  console.log('✅ igdux update complete');
  await browser.close();
})().catch(e => { console.error('❌ Puppeteer error:', e.message); process.exit(1); });
