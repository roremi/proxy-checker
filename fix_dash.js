const fs = require('fs');
let c = fs.readFileSync('public/dashboard.html', 'utf8');

const newStyle = `<style>
    :root{--bg:#09090b;--sb:#000000;--s1:#141416;--s2:#27272a;--s3:#3f3f46;--b1:#27272a;--b2:#3f3f46;--t1:#fafafa;--t2:#a1a1aa;--t3:#71717a;--bl:#3b82f6;--bl2:#60a5fa;--gr:#10b981;--rd:#ef4444;--or:#f59e0b;--pu:#8b5cf6;--sw:240px;--glass:rgba(255,255,255,0.03)}
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:var(--bg);color:var(--t1);font-family:'Inter',sans-serif;font-size:14px;display:flex;min-height:100vh;overflow-x:hidden}
    a{text-decoration:none;color:inherit}
    
    /* Sidebar */
    .sb{width:var(--sw);flex-shrink:0;background:rgba(0,0,0,0.4);backdrop-filter:blur(20px);border-right:1px solid var(--glass);display:flex;flex-direction:column;position:fixed;height:100vh;z-index:90;transition:.3s transform cubic-bezier(0.4,0,1,1)}
    .sb-logo{padding:20px 22px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--glass);flex-shrink:0}
    .sb-icon{width:38px;height:38px;background:linear-gradient(135deg,var(--bl2),var(--bl));border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 4px 20px rgba(59,130,246,.3), inset 0 1px 0 rgba(255,255,255,0.2)}
    .sb-name{font-weight:700;font-size:15px;color:var(--t1);line-height:1.2}.sb-ver{font-size:11px;color:var(--t3)}
    .sb-nav{padding:16px 12px;flex:1;overflow-y:auto}
    .nav-sep{font-size:11px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:.05em;margin:16px 10px 6px}
    .nav-a{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:10px;color:var(--t2);font-weight:500;transition:.2s;margin-bottom:2px}
    .nav-a:hover{background:var(--s2);color:var(--t1)}
    .nav-a.active{background:linear-gradient(90deg, rgba(59,130,246,.15), transparent);color:var(--bl2);border-left:2px solid var(--bl2);border-radius:0 10px 10px 0}
    .nav-a svg{width:18px;height:18px;opacity:.7}.nav-a.active svg{opacity:1}
    .sb-foot{padding:16px 12px;border-top:1px solid var(--glass)}
    .sb-foot .nav-a{width:100%;border:none;background:transparent;cursor:pointer;font-family:inherit;font-size:14px}
    
    /* Main Layout */
    .main{margin-left:var(--sw);flex:1;display:flex;flex-direction:column;min-width:0;min-height:100vh}
    .topbar{background:rgba(9,9,11,0.8);backdrop-filter:blur(20px);border-bottom:1px solid var(--glass);padding:0 30px;height:64px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:40}
    .burger{display:none;background:transparent;border:1px solid var(--b2);border-radius:8px;width:36px;height:36px;color:var(--t1);font-size:18px;cursor:pointer}
    .topbar-title{font-size:18px;font-weight:700;flex:1;letter-spacing:-0.5px}
    .topbar-meta{font-size:13px;color:var(--t3)}
    .topbar-ip{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.2);color:var(--gr);padding:5px 12px;border-radius:20px;font-size:12px;font-family:'SF Mono',monospace;font-weight:600}
    .content{padding:30px;flex:1;max-width:1400px;margin:0 auto;width:100%}
    
    /* Cards & Grids */
    .stat-grid{display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:20px;margin-bottom:30px}
    .stat-card{background:linear-gradient(180deg, var(--s1), transparent);border:1px solid var(--b1);border-radius:16px;padding:22px;display:flex;align-items:flex-start;gap:16px;transition:.2s;box-shadow:0 4px 20px rgba(0,0,0,0.2)}
    .stat-card:hover{border-color:var(--b2);transform:translateY(-2px);box-shadow:0 8px 30px rgba(0,0,0,0.4)}
    .stat-ic{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0;box-shadow:inset 0 1px 0 rgba(255,255,255,0.1)}
    .stat-body .lbl{font-size:12px;color:var(--t3);font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
    .stat-body .val{font-size:32px;font-weight:800;color:var(--t1);line-height:1;letter-spacing:-1px}
    .stat-body .sub{font-size:12px;color:var(--t2);margin-top:8px}
    
    .quick-grid{display:grid;grid-template-columns:repeat(auto-fit, minmax(260px, 1fr));gap:20px;margin-bottom:30px}
    .quick-btn{background:var(--s1);border:1px solid var(--b1);border-radius:16px;padding:20px;display:flex;align-items:center;gap:16px;cursor:pointer;transition:.2s;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
    .quick-btn:hover{background:var(--s2);border-color:var(--bl);box-shadow:0 6px 20px rgba(0,0,0,0.3)}
    .quick-btn .qi{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
    .quick-btn .qt{font-size:15px;font-weight:600;margin-bottom:2px}
    .quick-btn .qs{font-size:12px;color:var(--t3)}
    
    .grid-2{display:grid;grid-template-columns:repeat(auto-fit, minmax(400px, 1fr));gap:20px;margin-bottom:30px}
    .card{background:var(--s1);border:1px solid var(--glass);border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.2);margin-bottom:20px}
    .card-head{padding:18px 24px;border-bottom:1px solid var(--glass);display:flex;align-items:center;justify-content:space-between;background:rgba(255,255,255,0.01)}
    .card-head h2{font-size:15px;font-weight:700;display:flex;align-items:center;gap:8px}
    
    /* Tables */
    .table-responsive{overflow-x:auto}
    table{width:100%;border-collapse:collapse;min-width:500px}
    th{padding:12px 24px;text-align:left;font-size:11px;color:var(--t3);font-weight:600;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--glass);background:var(--bg)}
    td{padding:14px 24px;font-size:14px;border-bottom:1px solid var(--glass);vertical-align:middle}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:rgba(255,255,255,0.02)}
    
    /* Badges & Elements */
    .badge{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:20px;font-size:12px;font-weight:600;white-space:nowrap}
    .bg{background:rgba(16,185,129,.1);color:var(--gr);border:1px solid rgba(16,185,129,.2)}
    .br{background:rgba(239,68,68,.1);color:var(--rd);border:1px solid rgba(239,68,68,.2)}
    .bo{background:rgba(245,158,11,.1);color:var(--or);border:1px solid rgba(245,158,11,.2)}
    .bb{background:rgba(59,130,246,.1);color:var(--bl2);border:1px solid rgba(59,130,246,.2)}
    .bd{background:rgba(161,161,170,.1);color:var(--t2);border:1px solid rgba(161,161,170,.2)}
    .dot{width:6px;height:6px;border-radius:50%;background:currentColor}
    
    .btn{display:inline-flex;align-items:center;gap:8px;padding:8px 16px;border:1px solid var(--glass);background:var(--s2);color:var(--t1);border-radius:10px;cursor:pointer;font-size:13px;font-weight:600;transition:.2s;box-shadow:0 2px 5px rgba(0,0,0,0.2)}
    .btn:hover{background:var(--s3);border-color:var(--b2)}
    .btn-primary{background:linear-gradient(180deg, var(--bl2), var(--bl));border:none;color:#fff;box-shadow:0 4px 12px rgba(59,130,246,.4), inset 0 1px 0 rgba(255,255,255,0.3)}
    .btn-primary:hover{transform:translateY(-1px);box-shadow:0 6px 16px rgba(59,130,246,.5), inset 0 1px 0 rgba(255,255,255,0.3)}
    .btn-sm{padding:6px 12px;font-size:12px;border-radius:8px}
    
    /* System Resources Grid */
    .sys-grid{display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:20px;padding:24px}
    .sys-item .k{font-size:12px;color:var(--t3);font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px}
    .sys-item .v{font-size:16px;color:var(--t1);font-weight:700}
    .sys-item .sub{font-size:12px;color:var(--t2);margin-top:6px}
    .sys-bar{height:6px;background:var(--s3);border-radius:999px;margin-top:10px;overflow:hidden}
    .sys-fill{height:100%;border-radius:999px;background:var(--gr);transition:width .4s ease;width:0}
    .sys-fill.warn{background:var(--or)}
    .sys-fill.crit{background:var(--rd)}
    
    .prog{height:6px;background:var(--bg);border-radius:4px;margin-top:6px;overflow:hidden}
    .prog-bar{height:100%;border-radius:4px}.prog-ok{background:var(--gr)}.prog-warn{background:var(--or)}.prog-full{background:var(--rd)}
    
    .toast-wrap{position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column-reverse;gap:8px;pointer-events:none;max-width:360px}
    .toast{background:var(--s1);border:1px solid var(--glass);color:var(--t1);padding:14px 20px;border-radius:12px;font-size:14px;box-shadow:0 8px 32px rgba(0,0,0,.6);opacity:0;transform:translateY(10px);transition:.3s cubic-bezier(0.4,0,0.2,1);pointer-events:auto;font-weight:500}
    .toast.show{opacity:1;transform:translateY(0)}.toast.err{border-left:4px solid var(--rd)}.toast.ok{border-left:4px solid var(--gr)}
    
    .empty{text-align:center;padding:50px 20px;color:var(--t3);font-size:14px;font-weight:500}
    .mono{font-family:'SF Mono',Consolas,monospace;font-size:13px}
    .text-muted{color:var(--t2)}.text-dim{color:var(--t3)}.text-green{color:var(--gr)}.text-red{color:var(--rd)}
    .text-sm{font-size:13px}.text-xs{font-size:12px}
    ::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--s3);border-radius:10px}
    
    /* Responsive */
    @media(max-width:1024px){
      body.sb-open .sb{transform:translateX(0)}
      .sb{transform:translateX(-100%)}
      .main{margin-left:0}
      .burger{display:flex;align-items:center;justify-content:center}
      .topbar{padding:0 20px;gap:12px}
      .content{padding:20px}
    }
    @media(max-width:600px){
      .grid-2{grid-template-columns:1fr}
      .topbar-meta{display:none}
      .sys-grid{grid-template-columns:1fr}
    }
  </style>`;

c = c.replace(/<style>[\s\S]*?<\/style>/, newStyle);
c = c.replace(/<div class="topbar">/, `<div class="topbar">\n    <button class="burger" id="burger" onclick="document.body.classList.toggle('sb-open')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2=\"6\"></line><line x1="3" y1="18" x2="21" y2=\"18\"></line></svg></button>`);
c = c.replace(/<table>/g, `<div class="table-responsive"><table>`);
c = c.replace(/<\/table>/g, `</table></div>`);
c = c.replace(/<div class="sb-logo">/g, `<div class="sb-logo">\n    <button class="burger" onclick="document.body.classList.remove('sb-open')" style="position:absolute;right:10px;border:none;background:transparent;color:var(--t2);cursor:pointer;padding:6px;display:none;width:auto;height:auto;" id="cl-burger">×</button>`);

// Add display:block to close button on mobile
c = c.replace(/@media\(max-width:1024px\)\{/, `@media(max-width:1024px){\n      #cl-burger{display:block!important}`);

fs.writeFileSync('public/dashboard.html', c);
console.log('Fixed dashboard');