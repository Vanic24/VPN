const puppeteer = require('puppeteer');
const fs = require('fs');

(async () => {
  const url = process.env.IGDUX_EDIT_URL;
  if (!url) { console.error('Missing IGDUX_EDIT_URL secret'); process.exit(1); }

  const content = fs.readFileSync('9PB', 'utf8');

  const browser = await puppeteer.launch({
    headless: true, // Safe headless mode for GitHub Actions
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const page = await browser.newPage();

  await page.setExtraHTTPHeaders({ 'Accept': '*/*','Accept-Language': 'en-US,en;q=0.9' });

  console.log('🌐 Opening igdux editor...');
  await page.goto(url, { waitUntil: 'networkidle2', timeout: 60000 });

  // Wait for editor textarea or contenteditable element
  const selector = 'textarea, [contenteditable="true"], #editor, #app textarea';
  await page.waitForSelector(selector, { timeout: 30000 });

  // Detect if element is contenteditable
  const isContentEditable = await page.$eval(selector, el => el.getAttribute && el.getAttribute('contenteditable') === 'true');

  // Update content
  if (isContentEditable) {
    await page.$eval(selector, (el, txt) => { el.innerText = txt; }, content);
  } else {
    await page.$eval(selector, (el, txt) => { el.value = txt; el.dispatchEvent(new Event('input', { bubbles: true })); }, content);
  }

  console.log('💾 Attempting to save...');

  // Helper to safely click via XPath
  async function tryXPathClick(page, xpath) {
    try {
      const handles = await page.$x(xpath);
      if (handles.length > 0) { await handles[0].click(); return true; }
    } catch(e) {
      console.warn(`XPath ${xpath} failed: ${e.message}`);
    }
    return false;
  }

  const attempts = [
    "//button[contains(., 'Save')]",
    "//button[contains(., '保存')]",
    "//button[contains(., 'submit')]",
    "//input[@type='submit']",
    "//button[@type='submit']",
    "//button[contains(@class,'save')]"
  ];

  let saved = false;
  for (const xp of attempts) {
    if (await tryXPathClick(page, xp)) { saved = true; break; }
  }

  // Fallback: Ctrl+S / Cmd+S
  if (!saved) {
    const key = process.platform === 'darwin' ? 'Meta' : 'Control';
    await page.keyboard.down(key);
    await page.keyboard.press('KeyS');
    await page.keyboard.up(key);
  }

  await page.waitForTimeout(3000); // Wait for save
  console.log('✅ igdux update complete');

  await browser.close();
})().catch(e => {
  console.error('❌ Puppeteer error:', e.message);
  process.exit(1);
});
