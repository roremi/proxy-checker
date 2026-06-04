const fs = require('fs');
const path = require('path');
const d = path.join(__dirname, 'public');

const css = `
/* --- Modern UI Overrides --- */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
body { font-family: 'Inter', -apple-system, sans-serif; letter-spacing: -0.01em; }
.card { border-radius: 16px; box-shadow: 0 8px 30px -4px rgba(0,0,0,0.6); border: 1px solid rgba(255,255,255,0.07); background: linear-gradient(180deg, var(--s1), #121214); }
.card-head { border-bottom: 1px solid rgba(255,255,255,0.05); }
.btn { border-radius: 10px; box-shadow: 0 1px 2px rgba(0,0,0,0.3); font-weight: 600; transition: all 0.2s cubic-bezier(0.4,0,0.2,1); }
.btn-primary { background: linear-gradient(180deg, #4f46e5, #3b82f6); border: 1px solid transparent; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3), inset 0 1px 0 rgba(255,255,255,0.2); }
.btn-primary:hover { box-shadow: 0 6px 16px rgba(59, 130, 246, 0.5), inset 0 1px 0 rgba(255,255,255,0.2); filter: brightness(1.1); transform: translateY(-1px); }
input[type=text], input[type=password], input[type=number], select, textarea { border-radius: 10px; border: 1px solid rgba(255,255,255,0.1); background: rgba(0,0,0,0.2); box-shadow: inset 0 1px 3px rgba(0,0,0,0.2); transition: all 0.2s; }
input:focus, select:focus, textarea:focus { border-color: var(--bl); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2), inset 0 1px 2px rgba(0,0,0,0.2); }
.sb { border-right: 1px solid rgba(255,255,255,0.05); }
.topbar { background: rgba(9,9,11,0.7); backdrop-filter: blur(16px); border-bottom: 1px solid rgba(255,255,255,0.05); }
.nav-a { border-radius: 10px; }
.badge { border-radius: 99px; text-transform: uppercase; font-size: 10px; letter-spacing: 0.04em; padding: 3px 8px; }
`;

fs.readdirSync(d).filter(f => f.endsWith('.html')).forEach(f => {
  const p = path.join(d, f);
  let c = fs.readFileSync(p, 'utf8');
  if (!c.includes('/* --- Modern UI Overrides --- */')) {
    c = c.replace('</style>', css + '\n</style>');
    fs.writeFileSync(p, c);
  }
});
console.log('Injected overrides.');
