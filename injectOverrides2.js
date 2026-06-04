const fs = require('fs');
const d = './public';
let count = 0;
fs.readdirSync(d).filter(f => f.endsWith('.html')).forEach(f => {
  let p = d + '/' + f;
  let c = fs.readFileSync(p, 'utf8');
  let o = c;
  
  const css = `<style>
@import url("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap");
body { font-family: "Inter", -apple-system, sans-serif !important; letter-spacing: -0.01em; }
.card { background: linear-gradient(180deg, var(--s1), #09090b) !important; box-shadow: 0 12px 40px -8px rgba(0,0,0,0.6) !important; border-radius: 16px !important; border: 1px solid rgba(255,255,255,0.05) !important; }
.card-head { border-bottom: 1px solid rgba(255,255,255,0.05) !important; background: transparent !important; }
.btn { border-radius: 10px !important; box-shadow: 0 1px 2px rgba(0,0,0,0.3) !important; font-weight: 500 !important; transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important; }
.btn:hover { transform: translateY(-1px); }
.btn-primary { background: linear-gradient(180deg, #60a5fa, #3b82f6) !important; border: 1px solid transparent !important; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4), inset 0 1px 0 rgba(255,255,255,0.3) !important; color: #fff !important; text-shadow: 0 1px 1px rgba(0,0,0,0.2); }
.btn-primary:hover { box-shadow: 0 6px 16px rgba(59, 130, 246, 0.6), inset 0 1px 0 rgba(255,255,255,0.3) !important; filter: brightness(1.1); }
input[type=text], input[type=password], input[type=number], select, textarea { border-radius: 10px !important; background: rgba(0,0,0,0.2) !important; box-shadow: inset 0 1px 3px rgba(0,0,0,0.2) !important; border: 1px solid rgba(255,255,255,0.1) !important; }
input:focus, select:focus, textarea:focus { border-color: var(--bl) !important; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2), inset 0 1px 2px rgba(0,0,0,0.2) !important; }
.sb { background: #000 !important; border-right: 1px solid rgba(255,255,255,0.04) !important; }
.topbar { background: rgba(9, 9, 11, 0.7) !important; backdrop-filter: blur(20px) !important; border-bottom: 1px solid rgba(255,255,255,0.04) !important; }
.badge { text-transform: uppercase; font-size: 10px !important; letter-spacing: 0.05em; padding: 4px 10px !important; }
table th { text-transform: uppercase; font-size: 11px !important; letter-spacing: 0.05em; border-bottom: 1px solid rgba(255,255,255,0.05) !important; background: transparent !important; }
table tr { border-bottom: 1px solid rgba(255,255,255,0.03) !important; }
table tr:hover { background: rgba(255,255,255,0.02) !important; }
`;

  c = c.replace('<style>', css);
  
  if (o !== c) {
    fs.writeFileSync(p, c);
    count++;
  }
});
console.log('Injected detailed styles to', count, 'files.');
