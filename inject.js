const fs = require('fs');
const path = require('path');
const d = path.join(__dirname, 'public');

const css = `
/* --- Modern UI Overrides --- */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
body { font-family: 'Inter', -apple-system, sans-serif; letter-spacing: -0.01em; }
.card { border-radius: 16px; box-shadow: 0 12px 40px -8px rgba(0,0,0,0.6); border: 1px solid rgba(255,255,255,0.05); background: linear-gradient(180deg, var(--s1), #121214); }
.card-head { border-bottom: 1px solid rgba(255,255,255,0.05); background: transparent; padding: 16px 20px; }
.btn { border-radius: 9px; box-shadow: 0 1px 2px rgba(0,0,0,0.3); font-weight: 500; transition: all 0.2s cubic-bezier(0.4,0,0.2,1); }
.btn-primary { background: linear-gradient(180deg, #60a5fa, #3b82f6); border: 1px solid transparent; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4), inset 0 1px 0 rgba(255,255,255,0.3); color: #fff; text-shadow: 0 1px 1px rgba(0,0,0,0.2); }
.btn-primary:hover { box-shadow: 0 6px 16px rgba(59, 130, 246, 0.6), inset 0 1px 0 rgba(255,255,255,0.3); filter: brightness(1.1); transform: translateY(-1px); }
.btn-danger { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); box-shadow: none; color: #ef4444; }
.btn-danger:hover { background: rgba(239, 68, 68, 0.2); transform: translateY(-1px); }
input[type=text], input[type=password], input[type=number], select, textarea { border-radius: 9px; border: 1px solid rgba(255,255,255,0.08); background: rgba(0,0,0,0.25); box-shadow: inset 0 1px 3px rgba(0,0,0,0.3); transition: all 0.2s; }
input:focus, select:focus, textarea:focus { border-color: var(--bl); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2), inset 0 1px 2px rgba(0,0,0,0.3); background: rgba(0,0,0,0.4); }
.sb { border-right: 1px solid rgba(255,255,255,0.03); background: #000; }
.topbar { background: rgba(9, 9, 11, 0.65); backdrop-filter: blur(20px); border-bottom: 1px solid rgba(255,255,255,0.03); }
.nav-a { border-radius: 9px; font-weight: 500; }
.nav-a.active { background: rgba(255,255,255,0.05); color: #fff; border-color: transparent; box-shadow: 0 1px 2px rgba(0,0,0,0.2); }
.nav-sep { color: var(--t3); font-weight: 600; font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; }
.badge { border-radius: 99px; text-transform: uppercase; font-size: 10px; letter-spacing: 0.05em; padding: 4px 10px; box-shadow: 0 1px 2px rgba(0,0,0,0.2); }
.badge.bg { background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.2); color: #10b981; }
.stat-val { font-family: "Inter", sans-serif; font-weight: 700; letter-spacing: -0.02em; }
table th { text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; color: var(--t3); border-bottom: 1px solid rgba(255,255,255,0.05); background: transparent; }
table tr { border-bottom: 1px solid rgba(255,255,255,0.03); }
table tr:hover { background: rgba(255,255,255,0.015); }
.err { border-radius: 9px; border: 1px solid rgba(239, 68, 68, 0.2); background: rgba(239, 68, 68, 0.1); color: #ef4444; }
.hint { font-size: 13px; color: var(--t2); }
`;

let count = 0;
fs.readdirSync(d).filter(f => f.endsWith('.html')).forEach(f => {
  const p = path.join(d, f);
  let c = fs.readFileSync(p, 'utf8');
  if (!c.includes('/* --- Modern UI Overrides --- */')) {
    c = c.replace('</style>', css + '\n</style>');
    fs.writeFileSync(p, c);
    count++;
  }
});
console.log('Injected overrides to ' + count + ' files.');
