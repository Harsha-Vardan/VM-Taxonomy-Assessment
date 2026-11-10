// Captures the guided-simulation view for the IEEE paper: node scripts/capture_sim_figure.js
// Needs Playwright (npm i playwright) or ../QA/node_modules/playwright. Output: docs/paper/ieee/figs/fig_sim.png
const path = require('path');
let chromium;
try { ({ chromium } = require('playwright')); } catch (e) { ({ chromium } = require(path.join(__dirname, '..', '..', 'QA', 'node_modules', 'playwright'))); }
const root = path.join(__dirname, '..');
(async () => {
  const b = await chromium.launch();
  const pg = await b.newPage({ viewport: { width: 1500, height: 900 }, deviceScaleFactor: 2, colorScheme: 'light' });
  await pg.goto('file:///' + path.join(root, 'simulator.html').split(path.sep).join('/'));
  await pg.click('.vmcard:has-text("legacy-erp")');
  await pg.click('main .acard:has-text("Floppy-controller")');
  await pg.click('text=Skip animation');
  await pg.waitForSelector('text=Step 4: result');
  await pg.waitForTimeout(1500);
  const el = await pg.$('.simgrid');
  await el.screenshot({ path: path.join(root, 'docs', 'paper', 'ieee', 'figs', 'fig_sim.png') });
  await b.close();
  console.log('ok');
})();
