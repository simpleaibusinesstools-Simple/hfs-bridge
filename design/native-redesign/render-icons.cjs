const fs = require('node:fs');
const path = require('node:path');
const sharp = require('sharp');
const root = __dirname;
(async () => {
  for (const file of fs.readdirSync(path.join(root, 'icons')).filter(x => x.endsWith('.svg'))) {
    const original = fs.readFileSync(path.join(root, 'icons', file), 'utf8');
    for (const [variant, color] of Object.entries({ light: '#B6D2EB', mint: '#56F4DA', ink: '#061E28', disabled: '#7390A6' })) {
      const svg = original.replace(/fill="[^"]*"/g, `fill="${color}"`).replace('<svg ', `<svg color="${color}" `);
      await sharp(Buffer.from(svg)).resize(64,64).png().toFile(path.join(root, 'assets', `icon-${path.basename(file,'.svg')}-${variant}.png`));
    }
  }
  console.log('Rendered official Fluent icons to transparent PNGs.');
})();
