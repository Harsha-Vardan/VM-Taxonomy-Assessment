const path = require('path');
let chromium;
try { ({ chromium } = require('playwright')); } catch (e) { ({ chromium } = require(path.join(__dirname, '..', '..', 'QA', 'node_modules', 'playwright'))); }
const [, , htmlPath, pdfPath] = process.argv;
(async () => {
  const b = await chromium.launch();
  const pg = await b.newPage();
  await pg.goto('file:///' + htmlPath.split(String.fromCharCode(92)).join('/'), { waitUntil: 'load' });
  await pg.evaluate(() => Promise.all([...document.images].map(i => i.complete ? 1 : new Promise(r => { i.onload = i.onerror = r; }))));
  const broken = await pg.evaluate(() => [...document.images].filter(i => !i.naturalWidth).map(i => i.getAttribute('src')));
  await pg.pdf({
    path: pdfPath, format: 'A4', printBackground: true,
    margin: { top: '20mm', bottom: '20mm', left: '20mm', right: '20mm' },
    displayHeaderFooter: true,
    headerTemplate: '<div></div>',
    footerTemplate: '<div style="width:100%;font-size:8px;color:#555;font-family:Calibri,Arial,sans-serif;display:flex;justify-content:space-between;padding:0 20mm"><span>vsec: Taxonomy-Driven Security Assessment for KVM Virtualization</span><span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>',
  });
  console.log('broken images:', broken);
  await b.close();
})();
