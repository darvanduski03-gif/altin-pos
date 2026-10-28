
/* =========================================================
   ALTIN SERVER AUTH / RBAC v2
========================================================= */
const ALTIN_PERMS = {
  admin: ['*'],
  manager: ['dashboard.view','sales.view','sales.create','sales.edit','sales.delete','purchases.view','purchases.create','purchases.edit','purchases.delete','debts.create','debts.view','debts.edit','returns.view','returns.create','returns.edit','returns.delete','stock.view','stock.create','stock.edit','expenses.view','expenses.create','expenses.edit','customers.view','customers.create','customers.edit','customers.delete','reports.view','settings.view','settings.edit','backup.manage','audit.view'],
  cashier: ['dashboard.view','sales.view','sales.create','customers.view','customers.create','debts.create','debts.view','returns.view','returns.create'],
  seller: ['sales.view','sales.create','debts.view','debts.create','returns.view','returns.create'],
  warehouse: ['dashboard.view','purchases.view','purchases.create','purchases.edit','stock.view','stock.create','stock.edit'],
  accountant: ['dashboard.view','sales.view','purchases.view','returns.view','expenses.view','expenses.create','expenses.edit','customers.view','customers.create','customers.edit','debts.view','debts.create','debts.edit','reports.view','audit.view']
};
const ALTIN_ROLE_LABELS = {admin:'Admin — بەڕێوەبەری گشتی',manager:'Manager — بەڕێوەبەر',cashier:'Cashier — فرۆشیار',seller:'Seller — فرۆشیار (فرۆشتن و مرجوعات)',warehouse:'Warehouse — کۆگا',accountant:'Accountant — ژمێریار'};
// Per-isolate performance state; contains no user data or credentials.
let altinSchemaInitPromise = null;
let altinLastSessionCleanupAt = 0;
function altinRolePerms(u){
  if (!u) return [];
  if (u.role === 'admin') return ['*'];
  let custom=[]; try { custom=JSON.parse(u.permissions||'[]'); } catch {}
  return custom.length ? custom : (ALTIN_PERMS[u.role]||[]);
}
function altinCan(u,p){ const ps=altinRolePerms(u); return ps.includes('*') || ps.includes(p); }
function altinHashHex(buf){ return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join(''); }
function altinBytes(n){ const a=new Uint8Array(n); crypto.getRandomValues(a); return a; }
const ALTIN_PBKDF2_ITERATIONS = 100000;

async function altinPasswordHash(password, saltHex, iterations = ALTIN_PBKDF2_ITERATIONS){
  const safeIterations = Number(iterations);
  if (!Number.isInteger(safeIterations) || safeIterations < 1 || safeIterations > ALTIN_PBKDF2_ITERATIONS) {
    throw new Error('Unsupported PBKDF2 iteration count');
  }
  const salt = saltHex ? Uint8Array.from(saltHex.match(/.{1,2}/g).map(x=>parseInt(x,16))) : altinBytes(16);
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:safeIterations,hash:'SHA-256'}, base, 256);
  return `pbkdf2$${safeIterations}$${altinHashHex(salt.buffer)}$${altinHashHex(bits)}`;
}
async function altinVerifyPassword(password, stored){
  if (!stored) return false;
  if (!stored.startsWith('pbkdf2$')) return stored === password; // legacy users are upgraded on successful login
  const parts=stored.split('$');
  if(parts.length!==4) return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > ALTIN_PBKDF2_ITERATIONS) return false;
  const got=await altinPasswordHash(password,parts[2],iterations);
  return got===stored;
}
async function altinTokenHash(token){ return altinHashHex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token))); }
async function altinSessionUser(db, request){
  const token=request.headers.get('X-ALTIN-Token')||'';
  if(!token) return null;
  const h=await altinTokenHash(token);
  const row=await db.prepare(`SELECT u.id,u.username,u.name,u.role,u.permissions,u.active,s.expires_at FROM altin_sessions s JOIN altin_users u ON u.id=s.user_id WHERE s.token_hash=?`).bind(h).first();
  if(!row || !row.active || new Date(row.expires_at).getTime()<Date.now()) return null;
  return row;
}
async function altinRequire(db, request, perm){
  const u=await altinSessionUser(db,request);
  if(!u) return {error:true,response:{status:401,data:{success:false,error:'پێویستە بچیتە ژوورەوە.'}}};
  if(perm && !altinCan(u,perm)) return {error:true,response:{status:403,data:{success:false,error:'دەسەڵاتی ئەم کردارە نییە.'}}};
  return {user:u};
}
async function altinLogin(db, body, json, ctx, initialAdminPassword = ''){
  // Login must NEVER leak an exception to the Pages runtime. Any failure is
  // converted to a JSON response so the browser cannot receive Cloudflare HTML.
  let stage='validate';
  try {
    const username=String(body?.username||'').trim();
    const password=String(body?.password||'');
    if(!username || !password) return json({success:false,error:'ناوی بەکارهێنەر و وشەی نهێنی پێویستن',api:true,stage},400);

    stage='schema';
    await altinEnsureAuthSchema(db, initialAdminPassword);
    const accountCount = await db.prepare('SELECT COUNT(*) AS n FROM altin_users').first();
    if (Number(accountCount?.n || 0) === 0) {
      return json({success:false,error:'سیستەم هێشتا ئەدمینی سەرەتایی نییە. لە Cloudflare Pages Secret بە ناوی ALTIN_INITIAL_ADMIN_PASSWORD دابنێ (لانیکەم ١٢ پیت) و دووبارە هەوڵ بدەرەوە.',api:true,initializationRequired:true,stage:'bootstrap'},503);
    }

    stage='lookup';
    const u=await db.prepare('SELECT id,username,name,role,password,permissions,active FROM altin_users WHERE username=?').bind(username).first();
    if(!u || !Number(u.active)) return json({success:false,error:'ناوی بەکارهێنەر یان وشەی نهێنی هەڵەیە',api:true,stage},401);

    stage='password';
    const valid=await altinVerifyPassword(password,String(u.password||''));
    if(!valid) return json({success:false,error:'ناوی بەکارهێنەر یان وشەی نهێنی هەڵەیە',api:true,stage},401);

    // Upgrade old plaintext passwords only after a successful verification.
    if(!String(u.password||'').startsWith('pbkdf2$')) {
      stage='password-upgrade';
      try { const upgrade = altinPasswordHash(password).then(h => db.prepare('UPDATE altin_users SET password=? WHERE id=?').bind(h,u.id).run()).catch(()=>{}); if(ctx?.waitUntil) ctx.waitUntil(upgrade); } catch {}
    }

    stage='token';
    const raw=altinHashHex(altinBytes(32).buffer)+altinHashHex(altinBytes(16).buffer);
    const hash=await altinTokenHash(raw);
    const expires=new Date(Date.now()+7*86400000).toISOString();
    const sessionId=crypto.randomUUID();

    stage='session';
    // Remove an impossible hash collision before insert; this also keeps the
    // UNIQUE token_hash constraint safe without touching user/account data.
    await db.prepare('DELETE FROM altin_sessions WHERE token_hash=?').bind(hash).run();
    await db.prepare('INSERT INTO altin_sessions(id,user_id,token_hash,expires_at,date) VALUES(?,?,?,?,?)')
      .bind(sessionId,String(u.id),hash,expires,new Date().toISOString()).run();

    return json({success:true,token:raw,expiresAt:expires,user:{id:u.id,username:u.username,name:u.name,role:u.role,roleLabel:ALTIN_ROLE_LABELS[u.role]||u.role,permissions:altinRolePerms(u)} ,api:true});
  } catch(e) {
    const requestId = crypto.randomUUID();
    console.error('ALTIN login failed', {requestId, stage, message:String(e?.message||e||'Unknown error')});
    return json({success:false,error:'کێشەیەکی سێرڤەر لە login ڕوویدا. تکایە دواتر هەوڵ بدەرەوە.',api:true,stage,requestId},500);
  }
}
function altinAuthResponse(json,r){ return json(r.response.data,r.response.status); }
function altinAppendChangeGuard(statements, db){
  // `changes()` refers to the immediately preceding inventory UPDATE. If no row
  // was changed (deleted product, stale stock quantity, or concurrent checkout),
  // CHECK fails and Cloudflare D1 rolls back the entire transaction batch.
  statements.push(db.prepare("INSERT INTO altin_tx_guard(ok) SELECT CASE WHEN changes()=1 THEN 1 ELSE 0 END"));
  statements.push(db.prepare("DELETE FROM altin_tx_guard"));
}
async function altinBatchOrConflict(db, statements, json){
  try { await db.batch(statements); return null; }
  catch(e){
    const message=String(e?.message||e||'');
    if (/altin_tx_guard|CHECK constraint failed: ok\s*=\s*1/i.test(message)) {
      return json({success:false,error:'کۆگا لە کاتی مامەڵەکەدا گۆڕاوە؛ داتا نوێ بکەرەوە و دووبارە هەوڵ بدەرەوە.'},409);
    }
    throw e;
  }
}
async function altinTableColumns(db, table){
  const rows = await db.prepare(`PRAGMA table_info(${table})`).all();
  return new Set((rows.results||[]).map(r=>String(r.name)));
}
async function altinEnsureColumn(db, table, column, definition){
  const cols = await altinTableColumns(db, table);
  if(cols.has(column)) return;
  try {
    await db.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`).run();
  } catch (err) {
    // Multiple Cloudflare isolates can initialize the same D1 database at once.
    // If another request added the column between PRAGMA and ALTER, treat that
    // specific race as success; otherwise preserve the real error.
    const refreshed = await altinTableColumns(db, table);
    if(!refreshed.has(column)) throw err;
  }
}
async function altinEnsureAuthSchema(db, initialAdminPassword = ''){
  await db.prepare(`CREATE TABLE IF NOT EXISTS altin_users (id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,name TEXT DEFAULT '',role TEXT DEFAULT 'cashier',password TEXT DEFAULT '',permissions TEXT DEFAULT '[]',active INTEGER DEFAULT 1,date TEXT NOT NULL)`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS altin_sessions (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,token_hash TEXT UNIQUE NOT NULL,expires_at TEXT NOT NULL,date TEXT NOT NULL)`).run();

  // Safe migration for older ALTIN databases. Never drops or rewrites existing data.
  await altinEnsureColumn(db,'altin_users','name',"TEXT DEFAULT ''");
  await altinEnsureColumn(db,'altin_users','role',"TEXT DEFAULT 'cashier'");
  await altinEnsureColumn(db,'altin_users','password',"TEXT DEFAULT ''");
  await altinEnsureColumn(db,'altin_users','permissions',"TEXT DEFAULT '[]'");
  await altinEnsureColumn(db,'altin_users','active','INTEGER DEFAULT 1');
  await altinEnsureColumn(db,'altin_users','date',"TEXT DEFAULT ''");
  await altinEnsureColumn(db,'altin_sessions','user_id',"TEXT DEFAULT ''");
  await altinEnsureColumn(db,'altin_sessions','token_hash',"TEXT DEFAULT ''");
  await altinEnsureColumn(db,'altin_sessions','expires_at',"TEXT DEFAULT ''");
  await altinEnsureColumn(db,'altin_sessions','date',"TEXT DEFAULT ''");
  try { await db.prepare(`CREATE INDEX IF NOT EXISTS idx_altin_sessions_hash ON altin_sessions(token_hash)`).run(); } catch {}

  // Bootstrap an administrator only for a genuinely empty user table, and only
  // when the operator supplied a strong deployment secret. Never seed 12345.
  const userCount = await db.prepare('SELECT COUNT(*) AS n FROM altin_users').first();
  const hasAnyUser = Number(userCount?.n || 0) > 0;
  const bootstrapPassword = String(initialAdminPassword || '');
  if (!hasAnyUser && bootstrapPassword.length >= 12) {
    await db.prepare(`INSERT INTO altin_users(id,username,name,role,password,permissions,active,date) VALUES(?,?,?,?,?,?,?,?)`)
      .bind(crypto.randomUUID(),'admin','Administrator','admin',await altinPasswordHash(bootstrapPassword),JSON.stringify(['*']),1,new Date().toISOString()).run();
  } else if (!hasAnyUser && bootstrapPassword.length > 0 && bootstrapPassword.length < 12) {
    console.warn('ALTIN initial admin password not accepted: use at least 12 characters');
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Static pages/assets bypass API CORS logic and are served by the Pages asset binding.
    if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);

    const origin = request.headers.get("Origin") || "";
    const allowedOrigins = new Set([url.origin, "https://altin-system.pages.dev"]);
    if (origin && !allowedOrigins.has(origin)) {
      return new Response(JSON.stringify({success:false,error:'Origin ـی ئەم داواکارییە ڕێگەپێدراو نییە.'}), {
        status: 403,
        headers: {"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","Vary":"Origin","X-Content-Type-Options":"nosniff"}
      });
    }

    const corsHeaders = {
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-ALTIN-Token",
      "Cache-Control": "no-store",
      "Vary": "Origin",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Cross-Origin-Resource-Policy": "same-origin"
    };
    if (origin) corsHeaders["Access-Control-Allow-Origin"] = origin;

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json; charset=utf-8"
        }
      });

    const num = (v, d = 0) =>
      Number.isFinite(Number(v)) ? Number(v) : d;

    const uid = () => crypto.randomUUID();

    const allowed = new Set([
      "products",
      "sales",
      "purchases",
      "expenses",
      "debts",
      "returns",
      "payments",
      "audit",
      "stock-movements"
    ]);

    // Serve static files without touching D1. Previously even index.html and
    // other asset requests ran schema migrations and a session cleanup query.
    if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);

    try {
      // Schema checks/migrations are expensive. Run them once per Worker isolate,
      // and retry automatically if initialization fails.
      if (!altinSchemaInitPromise) {
        altinSchemaInitPromise = (async () => {
          await ensureSchema(env.DB);
          // Complete, additive schema repair for older ALTIN D1 databases.
          // Only missing columns are added; no business rows or tables are dropped.
          const legacyColumns = [
            ['products','name',"TEXT DEFAULT ''"], ['products','code',"TEXT DEFAULT ''"], ['products','buy','REAL DEFAULT 0'], ['products','sell','REAL DEFAULT 0'], ['products','qty','REAL DEFAULT 0'], ['products','min','REAL DEFAULT 0'],
            ['sales','date',"TEXT DEFAULT ''"], ['sales','items',"TEXT DEFAULT '[]'"], ['sales','total','REAL DEFAULT 0'], ['sales','customer',"TEXT DEFAULT ''"], ['sales','customerPhone',"TEXT DEFAULT ''"], ['sales','paymentType',"TEXT DEFAULT 'cash'"], ['sales','previousDebt','REAL DEFAULT 0'], ['sales','reason',"TEXT DEFAULT ''"], ['sales','subtotal','REAL DEFAULT 0'], ['sales','discount','REAL DEFAULT 0'], ['sales','paidAmount','REAL DEFAULT 0'], ['sales','debtAmount','REAL DEFAULT 0'],
            ['purchases','product',"TEXT DEFAULT ''"], ['purchases','qty','REAL DEFAULT 0'], ['purchases','price','REAL DEFAULT 0'], ['purchases','supplier',"TEXT DEFAULT ''"], ['purchases','date',"TEXT DEFAULT ''"], ['purchases','paymentType',"TEXT DEFAULT 'cash'"], ['purchases','paidAmount','REAL DEFAULT 0'], ['purchases','debtAmount','REAL DEFAULT 0'], ['purchases','total','REAL DEFAULT 0'], ['purchases','currency',"TEXT DEFAULT 'IQD'"], ['purchases','buyIQD','REAL DEFAULT 0'], ['purchases','batchId',"TEXT DEFAULT ''"],
            ['expenses','name',"TEXT DEFAULT ''"], ['expenses','amount','REAL DEFAULT 0'], ['expenses','date',"TEXT DEFAULT ''"],
            ['debts','name',"TEXT DEFAULT ''"], ['debts','amount','REAL DEFAULT 0'], ['debts','note',"TEXT DEFAULT ''"], ['debts','date',"TEXT DEFAULT ''"], ['debts','currency',"TEXT DEFAULT 'IQD'"],
            ['returns','date',"TEXT DEFAULT ''"], ['returns','items',"TEXT DEFAULT '[]'"], ['returns','total','REAL DEFAULT 0'], ['returns','customer',"TEXT DEFAULT ''"], ['returns','reason',"TEXT DEFAULT ''"],
            ['payments','debtId',"TEXT DEFAULT ''"], ['payments','customer',"TEXT DEFAULT ''"], ['payments','amount','REAL DEFAULT 0'], ['payments','currency',"TEXT DEFAULT 'IQD'"], ['payments','note',"TEXT DEFAULT ''"], ['payments','date',"TEXT DEFAULT ''"], ['payments','paymentMethod',"TEXT DEFAULT 'نەقد'"],
            ['audit_logs','date',"TEXT DEFAULT ''"], ['audit_logs','action',"TEXT DEFAULT ''"], ['audit_logs','entity',"TEXT DEFAULT ''"], ['audit_logs','entityId',"TEXT DEFAULT ''"], ['audit_logs','details',"TEXT DEFAULT ''"], ['audit_logs','actor',"TEXT DEFAULT ''"],
            ['stock_movements','date',"TEXT DEFAULT ''"], ['stock_movements','productId',"TEXT DEFAULT ''"], ['stock_movements','type',"TEXT DEFAULT ''"], ['stock_movements','qty','REAL DEFAULT 0'], ['stock_movements','beforeQty','REAL DEFAULT 0'], ['stock_movements','afterQty','REAL DEFAULT 0'], ['stock_movements','refId',"TEXT DEFAULT ''"], ['stock_movements','note',"TEXT DEFAULT ''"]
          ];
          const legacyByTable = new Map();
          for (const [table, column, definition] of legacyColumns) {
            if (!legacyByTable.has(table)) legacyByTable.set(table, []);
            legacyByTable.get(table).push([column, definition]);
          }
          for (const [table, columns] of legacyByTable) {
            let have = await altinTableColumns(env.DB, table);
            for (const [column, definition] of columns) {
              if (have.has(column)) continue;
              try {
                await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`).run();
                have.add(column);
              } catch (err) {
                // A parallel cold start may have completed this migration.
                have = await altinTableColumns(env.DB, table);
                if (!have.has(column)) throw err;
              }
            }
          }
          // Add purchase settlement fields safely for existing databases.
          await altinEnsureColumn(env.DB, 'purchases', 'paymentType', "TEXT DEFAULT 'cash'");
          await altinEnsureColumn(env.DB, 'purchases', 'paidAmount', 'REAL DEFAULT 0');
          await altinEnsureColumn(env.DB, 'purchases', 'debtAmount', 'REAL DEFAULT 0');
          await altinEnsureColumn(env.DB, 'purchases', 'total', 'REAL DEFAULT 0');
          // Currency fields for purchase-debt tracking. Existing rows remain IQD.
          await altinEnsureColumn(env.DB, 'purchases', 'currency', "TEXT DEFAULT 'IQD'");
          await altinEnsureColumn(env.DB, 'debts', 'currency', "TEXT DEFAULT 'IQD'");
          await altinEnsureColumn(env.DB, 'payments', 'currency', "TEXT DEFAULT 'IQD'");
          await altinEnsureColumn(env.DB, 'payments', 'paymentMethod', "TEXT DEFAULT 'نەقد'");
          // Existing historical purchases were recorded as paid in full.
          await env.DB.prepare("UPDATE purchases SET total=COALESCE(NULLIF(total,0),price*qty), paidAmount=CASE WHEN paymentType IS NULL OR paymentType='cash' THEN price*qty ELSE COALESCE(paidAmount,0) END, debtAmount=CASE WHEN paymentType IS NULL OR paymentType='cash' THEN 0 ELSE COALESCE(debtAmount,0) END, paymentType=COALESCE(paymentType,'cash') WHERE total IS NULL OR total=0 OR paymentType IS NULL").run();
          // Repair legacy rows where newly-added default-zero settlement columns obscured
          // an older cash purchase. A cash purchase is fully paid by definition.
          await env.DB.prepare("UPDATE purchases SET total=COALESCE(NULLIF(total,0),price*qty), paidAmount=COALESCE(NULLIF(paidAmount,0),COALESCE(NULLIF(total,0),price*qty)), debtAmount=0 WHERE LOWER(COALESCE(paymentType,'cash'))='cash' AND COALESCE(paidAmount,0)=0").run();
          // Rebuild only clearly-unpaid legacy credit purchases with no settlement history
          // and no live debt row. Do not resurrect debts with any recorded payment.
          await env.DB.prepare("UPDATE purchases SET total=COALESCE(NULLIF(total,0),price*qty), debtAmount=COALESCE(NULLIF(total,0),price*qty), paidAmount=0 WHERE LOWER(COALESCE(paymentType,''))='credit' AND COALESCE(paidAmount,0)=0 AND COALESCE(debtAmount,0)=0 AND COALESCE(NULLIF(total,0),price*qty)>0 AND NOT EXISTS (SELECT 1 FROM debts d WHERE d.id='purchase-'||purchases.id) AND NOT EXISTS (SELECT 1 FROM payments pm WHERE pm.debtId='purchase-'||purchases.id)").run();
          await env.DB.prepare("UPDATE purchases SET total=COALESCE(NULLIF(total,0),price*qty), debtAmount=MAX(0,COALESCE(NULLIF(total,0),price*qty)-COALESCE(paidAmount,0)) WHERE LOWER(COALESCE(paymentType,''))='credit' AND COALESCE(paidAmount,0)>0 AND COALESCE(debtAmount,0)=0 AND COALESCE(NULLIF(total,0),price*qty)>COALESCE(paidAmount,0) AND NOT EXISTS (SELECT 1 FROM debts d WHERE d.id='purchase-'||purchases.id) AND NOT EXISTS (SELECT 1 FROM payments pm WHERE pm.debtId='purchase-'||purchases.id)").run();
          await env.DB.prepare("INSERT INTO debts (id,name,amount,note,date,currency) SELECT 'purchase-'||p.id, COALESCE(NULLIF(TRIM(p.supplier),''),'فرۆشیاری نەناسراو'), p.debtAmount, 'قەرزی کڕین • ژمارە: '||p.id, COALESCE(p.date,''), COALESCE(p.currency,'IQD') FROM purchases p WHERE COALESCE(p.debtAmount,0)>0 AND LOWER(COALESCE(p.paymentType,''))='credit' AND NOT EXISTS (SELECT 1 FROM debts d WHERE d.id='purchase-'||p.id) AND NOT EXISTS (SELECT 1 FROM payments pm WHERE pm.debtId='purchase-'||p.id)").run();
          await ensureMegaSchema(env.DB);
          await altinEnsureAuthSchema(env.DB, env.ALTIN_INITIAL_ADMIN_PASSWORD);
          // Store an IQD-normalized unit cost separately from the purchase's native currency.
          // Historical rows are backfilled once; product.buy follows the latest USD purchase
          // only where the old implementation had saved its raw USD amount as if it were IQD.
          const currencyFixDone = await megaGet(env.DB, "accountingCurrencyMigrationV1", false);
          if (currencyFixDone !== true) {
            const fx = Math.min(1000000000, Math.max(1, Number(await megaGet(env.DB, "usdRate", 1310)) || 1310));
            await env.DB.prepare("UPDATE purchases SET buyIQD=CASE WHEN UPPER(COALESCE(currency,'IQD'))='USD' THEN price*? ELSE price END WHERE COALESCE(buyIQD,0)=0").bind(fx).run();
            await env.DB.prepare(`UPDATE products SET buy=(SELECT p.buyIQD FROM purchases p WHERE p.product=products.id ORDER BY p.date DESC, p.rowid DESC LIMIT 1) WHERE EXISTS (SELECT 1 FROM purchases latest WHERE latest.product=products.id AND UPPER(COALESCE((SELECT p2.currency FROM purchases p2 WHERE p2.product=products.id ORDER BY p2.date DESC, p2.rowid DESC LIMIT 1),'IQD'))='USD')`).run();
            await megaSet(env.DB, "accountingCurrencyMigrationV1", true);
          }
          // Backfill only missing cost snapshots in old invoices/returns. Existing
          // snapshots are never rewritten, and no sales, purchases, or returns are deleted.
          await altinMigrateCostSnapshots(env.DB);
        })().catch(err => { altinSchemaInitPromise = null; throw err; });
      }
      await altinSchemaInitPromise;

      // Expired sessions do not need to be deleted on every API request.
      // Run cleanup at most once per five minutes in this isolate, off the response path.
      const cleanupNow = Date.now();
      if (cleanupNow - altinLastSessionCleanupAt > 5 * 60 * 1000) {
        altinLastSessionCleanupAt = cleanupNow;
        const cleanup = env.DB.prepare("DELETE FROM altin_sessions WHERE expires_at < ?")
          .bind(new Date(cleanupNow).toISOString()).run().catch(() => {});
        if (ctx?.waitUntil) ctx.waitUntil(cleanup);
      }

      /* ================= HEALTH ================= */

      if (path === "/api/health" && request.method === "GET") {
        try {
          await env.DB.prepare("SELECT 1").first();
          await env.DB.prepare(
            "SELECT COUNT(*) AS n FROM payments"
          ).first();

          await env.DB.prepare(
            "SELECT COUNT(*) AS n FROM audit_logs"
          ).first();

          return json({
            status: "OK",
            database: "OK",
            payments: "OK",
            audit: "OK",
            version: "ALTIN Production v15 - Cost Snapshots & Cashbox Fix"
          });
        } catch (err) {
          const requestId = crypto.randomUUID();
          console.error('ALTIN health check failed', {requestId, message:String(err?.message||err||'Unknown error')});
          return json(
            {
              status: "ERROR",
              database: "ERROR",
              payments: "ERROR",
              audit: "ERROR",
              error: "Health check failed",
              requestId
            },
            503
          );
        }
      }

      /* ================= AUTH ================= */
      if (path === '/api/auth/login' && request.method === 'POST') { let body={}; try { body=await request.json(); } catch { return json({success:false,error:'داتای login دروست نییە.',api:true,stage:'body'},400); } return altinLogin(env.DB, body, json, ctx, env.ALTIN_INITIAL_ADMIN_PASSWORD); }
      if (path === '/api/mega/login' && request.method === 'POST') return altinLogin(env.DB, await request.json(), json, ctx, env.ALTIN_INITIAL_ADMIN_PASSWORD);
      if (path === '/api/auth/status' && request.method === 'GET') {
        const a = await altinRequire(env.DB, request, 'users.view');
        if (a.error) return altinAuthResponse(json, a);
        try {
          const userCount=await env.DB.prepare('SELECT COUNT(*) AS n FROM altin_users').first();
          const sessionCount=await env.DB.prepare('SELECT COUNT(*) AS n FROM altin_sessions').first();
          return json({success:true,api:true,database:true,users:Number(userCount?.n||0),sessions:Number(sessionCount?.n||0)});
        } catch(e) {
          const requestId = crypto.randomUUID();
          console.error('ALTIN auth status failed', {requestId, message:String(e?.message||e||'Unknown error')});
          return json({success:false,api:true,error:'Auth status check failed',requestId},500);
        }
      }

      if (path === '/api/auth/me' && request.method === 'GET') {
        const a=await altinRequire(env.DB,request,null); if(a.error) return altinAuthResponse(json,a);
        return json({success:true,user:{id:a.user.id,username:a.user.username,name:a.user.name,role:a.user.role,roleLabel:ALTIN_ROLE_LABELS[a.user.role]||a.user.role,permissions:altinRolePerms(a.user)}});
      }
      if (path === '/api/auth/logout' && request.method === 'POST') {
        const token=request.headers.get('X-ALTIN-Token')||''; if(token) await env.DB.prepare('DELETE FROM altin_sessions WHERE token_hash=?').bind(await altinTokenHash(token)).run();
        return json({success:true});
      }
      if (path === '/api/auth/profile' && request.method === 'PUT') {
        const a=await altinRequire(env.DB,request,null); if(a.error) return altinAuthResponse(json,a);
        const d=await request.json(); const username=String(d.username||a.user.username).trim(); const name=String(d.name||a.user.name||username); const password=String(d.password||'');
        if(!username) return json({error:'username پێویستە'},400);
        try { if(password) await env.DB.prepare('UPDATE altin_users SET username=?,name=?,password=? WHERE id=?').bind(username,name,await altinPasswordHash(password),a.user.id).run(); else await env.DB.prepare('UPDATE altin_users SET username=?,name=? WHERE id=?').bind(username,name,a.user.id).run(); return json({success:true,username,name}); } catch(e){ return json({error:'ئەم username ـە پێشتر بەکارهاتووە'},409); }
      }
      /* ================= ALL DATA ================= */

      if (path === "/api/all" && request.method === "GET") {
        const a=await altinRequire(env.DB,request,null); if(a.error) return altinAuthResponse(json,a);
        const canLoadAny = ['dashboard.view','sales.view','stock.view','purchases.view','returns.view','customers.view','reports.view','expenses.view'].some(p=>altinCan(a.user,p));
        if (!canLoadAny) return json({success:false,error:'دەسەڵاتی بینینی داتا نییە.'},403);
        const [
          products,
          sales,
          purchases,
          expenses,
          debts,
          returns,
          payments,
          audit
        ] = await Promise.all([
          env.DB.prepare(
            "SELECT * FROM products ORDER BY name COLLATE NOCASE"
          ).all(),

          env.DB.prepare(
            "SELECT * FROM sales ORDER BY date DESC, rowid DESC"
          ).all(),

          env.DB.prepare(
            "SELECT * FROM purchases ORDER BY date DESC"
          ).all(),

          env.DB.prepare(
            "SELECT * FROM expenses ORDER BY date DESC"
          ).all(),

          env.DB.prepare(
            "SELECT * FROM debts ORDER BY date DESC"
          ).all(),

          env.DB.prepare(
            "SELECT * FROM returns ORDER BY date DESC"
          ).all(),

          env.DB.prepare(
            "SELECT * FROM payments ORDER BY date DESC"
          ).all(),

          env.DB.prepare(
            "SELECT * FROM audit_logs ORDER BY date DESC LIMIT 500"
          ).all()
        ]);

        const canBuy=altinCan(a.user,"purchases.view");
        const canExpense=altinCan(a.user,"expenses.view");
        const canSales=altinCan(a.user,"sales.view");
        const canStock=altinCan(a.user,"stock.view");
        const canReturns=altinCan(a.user,"returns.view");
        const canDebts=altinCan(a.user,"debts.view");
        const canCustomerData=altinCan(a.user,"customers.view");
        const canAudit=altinCan(a.user,"audit.view");
        const safeProducts=(products.results||[]).filter(()=>canBuy||canStock||canSales).map(p=>canBuy?p:{...p,buy:null});
        const safeDebts=canDebts ? (debts.results||[]).filter(d=>canBuy || !(String(d.id||'').startsWith('purchase-') || String(d.note||'').includes('قەرزی کڕین'))) : [];
        // A user who can view customer debts also needs the corresponding payment
        // history to see accurate remaining balances after an account is settled.
        // Supplier payments stay hidden unless the role can view purchases.
        const safePayments=(payments.results||[]).filter(p=>canBuy || !(String(p.debtId||'').startsWith('purchase-') || String(p.note||'').includes('قەرزی کڕین')));
        return json({
          products: safeProducts,
          sales: canSales ? parseItems(sales) : [],
          purchases: canBuy ? purchases.results : [],
          expenses: canExpense ? expenses.results : [],
          debts: safeDebts,
          returns: canReturns ? parseItems(returns) : [],
          payments: (canCustomerData || canBuy || canDebts) ? safePayments : [],
          audit: canAudit ? audit.results : []
        });
      }

      /* ================= BACKUP / RESTORE ================= */
      const backupTables = ["products","sales","purchases","expenses","debts","returns","payments","stock_movements","audit_logs","altin_settings"];
      if (path === "/api/backup" && request.method === "GET") {
        const auth = await altinRequire(env.DB, request, "backup.manage");
        if (auth.error) return altinAuthResponse(json, auth);
        if (auth.user.role !== "admin") return json({success:false,error:"تەنها بەڕێوەبەری گشتی دەتوانێت Backup وەرگرێت."},403);
        const tables = {};
        for (const table of backupTables) {
          const exists = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").bind(table).first();
          if (!exists) { tables[table] = []; continue; }
          const result = await env.DB.prepare(`SELECT * FROM ${table}`).all();
          tables[table] = result.results || [];
        }
        return json({success:true,format:"ALTIN_D1_BACKUP",version:1,createdAt:new Date().toISOString(),tables,counts:Object.fromEntries(Object.entries(tables).map(([k,v])=>[k,v.length]))});
      }
      if (path === "/api/backup/restore" && request.method === "POST") {
        const auth = await altinRequire(env.DB, request, "backup.manage");
        if (auth.error) return altinAuthResponse(json, auth);
        if (auth.user.role !== "admin") return json({success:false,error:"تەنها بەڕێوەبەری گشتی دەتوانێت Backup بگەڕێنێتەوە."},403);
        const body = await request.json().catch(()=>null);
        if (!body || body.confirmation !== "RESTORE ALTIN" || body.backup?.format !== "ALTIN_D1_BACKUP" || !body.backup.tables || typeof body.backup.tables !== "object") return json({success:false,error:"فایلی Backup یان پشتڕاستکردنەوە دروست نییە."},400);
        const source = body.backup.tables;
        const present = {};
        let totalRows = 0;
        const quoteSqlName = name => '"' + String(name).replace(/"/g, '""') + '"';
        // Preflight the complete restore before touching live business tables.
        // Older backups may omit newer tables; those tables are left untouched.
        for (const table of backupTables) {
          if (!Object.prototype.hasOwnProperty.call(source, table)) continue;
          if (!Array.isArray(source[table])) return json({success:false,error:`داتای ${table} لە Backup دروست نییە.`},400);
          const exists = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").bind(table).first();
          if (!exists) continue;
          const cols = await altinTableColumns(env.DB, table);
          const rows = source[table];
          totalRows += rows.length;
          if (rows.length > 20000 || totalRows > 60000) return json({success:false,error:`ژمارەی داتای Backup زۆرە؛ ${table} یان کۆی داتاکان سنووری گونجاو تێپەڕاندووە.`},413);
          for (const row of rows) {
            if (!row || typeof row !== 'object' || Array.isArray(row)) return json({success:false,error:`داتای Backup لە ${table} تێکچووە.`},400);
            const keys = Object.keys(row).filter(k => cols.has(k));
            if (!keys.length) return json({success:false,error:`هێڵێکی Backup لە ${table} هیچ ستوونێکی ناسراوی نییە.`},400);
            for (const key of keys) {
              const value = row[key];
              if (value !== null && !['string','number','boolean'].includes(typeof value)) return json({success:false,error:`جۆری داتای ستوونی ${key} لە ${table} پشتیوانی ناکرێت.`},400);
              if (typeof value === 'number' && !Number.isFinite(value)) return json({success:false,error:`ژمارەی نادروست لە ${table}.`},400);
            }
          }
          const schemaRow = await env.DB.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name=?").bind(table).first();
          const ddl = String(schemaRow?.sql || '');
          const tablePattern = new RegExp(`^(CREATE\\s+TABLE(?:\\s+IF\\s+NOT\\s+EXISTS)?\\s+)(\\"?${table}\\"?)\\s*\\(`, 'i');
          if (!ddl || !tablePattern.test(ddl)) return json({success:false,error:`شێوەی داتابەیسی ${table} بۆ Restore ناسراو نییە؛ هیچ داتایەک نەگۆڕدرا.`},409);
          const stageName = `altin_stage_${crypto.randomUUID().replace(/-/g,'')}_${table}`;
          const stageDdl = ddl.replace(tablePattern, (_m, prefix) => `${prefix}${quoteSqlName(stageName)} (`);
          present[table] = {cols, rows, stageName, stageDdl};
        }

        // Write to isolated staging tables first, in small batches. If any row is
        // invalid, live business tables remain untouched. The final swap is one
        // D1 batch/transaction, so a failed insert cannot leave a half-restored POS.
        try {
          const entries = Object.entries(present);
          if (!entries.length) return json({success:false,error:'لە Backup هیچ خشتەیەکی ناسراو نەدۆزرایەوە.'},400);
          await env.DB.batch(entries.map(([,entry]) => env.DB.prepare(`DROP TABLE IF EXISTS ${quoteSqlName(entry.stageName)}`)));
          await env.DB.batch(entries.map(([,entry]) => env.DB.prepare(entry.stageDdl)));

          let batch = [];
          for (const [table, entry] of entries) {
            for (const row of entry.rows) {
              const keys = Object.keys(row).filter(k => entry.cols.has(k));
              const sql = `INSERT INTO ${quoteSqlName(entry.stageName)} (${keys.map(quoteSqlName).join(',')}) VALUES (${keys.map(()=>'?').join(',')})`;
              batch.push(env.DB.prepare(sql).bind(...keys.map(k => typeof row[k] === 'boolean' ? (row[k] ? 1 : 0) : row[k] === undefined ? null : row[k])));
              if (batch.length >= 80) { await env.DB.batch(batch); batch = []; }
            }
          }
          if (batch.length) await env.DB.batch(batch);

          const swapStatements = [];
          for (const [table] of entries) swapStatements.push(env.DB.prepare(`DELETE FROM ${quoteSqlName(table)}`));
          for (const [table, entry] of entries) swapStatements.push(env.DB.prepare(`INSERT INTO ${quoteSqlName(table)} SELECT * FROM ${quoteSqlName(entry.stageName)}`));
          if (present.audit_logs) {
            swapStatements.push(env.DB.prepare("INSERT INTO audit_logs(id,date,action,entity,entityId,details,actor) VALUES(?,?,?,?,?,?,?)")
              .bind(crypto.randomUUID(),new Date().toISOString(),"RESTORE_BACKUP","system","",JSON.stringify({counts:Object.fromEntries(entries.map(([k,v])=>[k,v.rows.length]))}),auth.user.username));
          }
          for (const [,entry] of entries) swapStatements.push(env.DB.prepare(`DROP TABLE ${quoteSqlName(entry.stageName)}`));
          await env.DB.batch(swapStatements);
          return json({success:true,counts:Object.fromEntries(entries.map(([k,v])=>[k,v.rows.length]))});
        } catch (e) {
          // Staging cleanup never touches live tables; after a failed atomic swap,
          // the original business data is rolled back by D1.
          const entries = Object.values(present);
          if (entries.length) {
            await env.DB.batch(entries.map(entry => env.DB.prepare(`DROP TABLE IF EXISTS ${quoteSqlName(entry.stageName)}`))).catch(()=>{});
          }
          const requestId = crypto.randomUUID();
          console.error('ALTIN backup restore failed', {requestId, message:String(e?.message||e||'Unknown error')});
          return json({success:false,error:"گەڕاندنەوە تەواو نەبوو؛ داتای پێشوو پارێزراوە. Backup ـەکە بپشکنە و ئەگەر هەڵەکە بەردەوام بوو پەیوەندی بە پشتگیری بکە.",requestId},500);
        }
      }

      if (path === "/api/transactions/purchase/edit" && (request.method === "PUT" || request.method === "POST")) {
        const a=await altinRequire(env.DB,request,"purchases.edit"); if(a.error) return altinAuthResponse(json,a);
        let data={}; try { data=await request.json(); } catch { return json({success:false,error:"داتای دەستکاری کڕین دروست نییە."},400); }
        data.actor=a.user.username;
        return editPurchaseTransaction(data,env.DB,json);
      }

      /* ================= TRANSACTIONS ================= */

      if (path === "/api/transactions/sale/edit" && (request.method === "PUT" || request.method === "POST")) {
        const a=await altinRequire(env.DB,request,"sales.edit"); if(a.error) return altinAuthResponse(json,a);
        let data; try { data=await request.json(); } catch { return json({success:false,error:'داتای دەستکاری فاکتۆر دروست نییە.'},400); }
        data.actor=a.user.username;
        return editSaleTransaction(data,env.DB,json);
      }

      if (
        path === "/api/transactions/sale" &&
        request.method === "POST"
      ) {
        const a=await altinRequire(env.DB,request,"sales.create"); if(a.error) return altinAuthResponse(json,a);

        const data = await request.json(); data.actor = a.user.username;
        return saleTransaction(data, env.DB, json);
      }

      if (
        path === "/api/transactions/purchase/batch" &&
        request.method === "POST"
      ) {
        const a=await altinRequire(env.DB,request,"purchases.create"); if(a.error) return altinAuthResponse(json, a);
        let data={}; try { data=await request.json(); } catch { return json({success:false,error:"داتای سەبەتەی کڕین دروست نییە."},400); }
        data.actor = a.user.username;
        return purchaseBatchTransaction(data, env.DB, json);
      }

      if (
        path === "/api/transactions/purchase" &&
        request.method === "POST"
      ) {
        const a=await altinRequire(env.DB,request,"purchases.create"); if(a.error) return altinAuthResponse(json,a);

        const data = await request.json(); data.actor = a.user.username;
        return purchaseTransaction(data, env.DB, json);
      }

      if (
        path === "/api/transactions/return" &&
        request.method === "POST"
      ) {
        const a=await altinRequire(env.DB,request,"returns.create"); if(a.error) return altinAuthResponse(json,a);

        const data = await request.json(); data.actor = a.user.username;
        return returnTransaction(data, env.DB, json);
      }

      if (path === "/api/payments" && request.method === "POST") {
        const data = await request.json();
        const auth = await altinRequire(env.DB, request, null);
        if (auth.error) return altinAuthResponse(json, auth);
        const debt = await env.DB.prepare("SELECT id,note FROM debts WHERE id=?").bind(String(data.debtId || "")).first();
        if (!debt) return json({success:false,error:"Debt not found"},404);
        const isPurchaseDebt = String(debt.id).startsWith("purchase-") || String(debt.note || "").includes("قەرزی کڕین");
        const needed = isPurchaseDebt ? "purchases.view" : "customers.view";
        if (!altinCan(auth.user, needed)) return json({success:false,error:"دەسەڵاتی پارەدانی ئەم قەرزەت نییە."},403);
        data.actor = auth.user.username;
        return paymentTransaction(data, env.DB, json);
      }

      /* ================= AUDIT ================= */

      if (
        path === "/api/audit" &&
        request.method === "GET"
      ) {
        const a=await altinRequire(env.DB,request,"audit.view"); if(a.error) return altinAuthResponse(json,a);
        const limit = Math.min(
          Math.max(
            Number(url.searchParams.get("limit") || 200),
            1
          ),
          500
        );

        const rows = await env.DB
          .prepare(
            "SELECT * FROM audit_logs ORDER BY date DESC LIMIT ?"
          )
          .bind(limit)
          .all();

        return json({
          audit: rows.results || []
        });
      }

      if (
        path === "/api/audit" &&
        request.method === "POST"
      ) {
        const auth = await altinRequire(env.DB, request, null);
        if (auth.error) return altinAuthResponse(json, auth);
        let event;
        try { event = await request.json(); }
        catch { return json({success:false,error:'داتای Audit دروست نییە.'},400); }
        if (!event || typeof event !== 'object' || Array.isArray(event)) {
          return json({success:false,error:'داتای Audit دروست نییە.'},400);
        }
        const details = typeof event.details === 'string' ? event.details : JSON.stringify(event.details ?? {});
        if (details.length > 8000) return json({success:false,error:'زانیاری Audit زۆر درێژە.'},413);
        const trustedEvent = {
          id: crypto.randomUUID(),
          date: new Date().toISOString(),
          action: String(event.action || 'CHANGE').slice(0,80),
          entity: String(event.entity || '').slice(0,80),
          entityId: String(event.entityId || '').slice(0,160),
          details,
          actor: String(auth.user.username || 'unknown').slice(0,100)
        };
        return auditInsert(trustedEvent, env.DB, json);
      }


      /* ================= ALTIN MEGA API ================= */

      if (path === "/api/mega/summary" && request.method === "GET") {
        const a=await altinRequire(env.DB,request,"dashboard.view"); if(a.error) return altinAuthResponse(json,a);
        return json(await megaSummary(env.DB, a.user));
      }

      if (path === "/api/mega/settings" && request.method === "GET") {
        // The shared exchange rate is required for consistent debt and stock displays
        // on every authorized workstation; these operational settings are not secret.
        const a=await altinRequire(env.DB,request,null); if(a.error) return altinAuthResponse(json,a);
        const currency = await megaGet(env.DB,"currency","IQD");
        const usdRate = await megaGet(env.DB,"usdRate",1310);
        const returnDays = await megaGet(env.DB,"returnDays",3);
        const openingCash = await megaGet(env.DB,"openingCash",0);
        const dailySalesTarget = await megaGet(env.DB,"dailySalesTarget",90000);
        const targetGrossMargin = await megaGet(env.DB,"targetGrossMargin",40);
        return json({success:true,settings:{currency,usdRate,returnDays,openingCash,dailySalesTarget,targetGrossMargin}});
      }

      if (path === "/api/mega/settings" && request.method === "PUT") {
        const a=await altinRequire(env.DB,request,"settings.edit"); if(a.error) return altinAuthResponse(json,a);
        const d=await request.json().catch(()=>null);
        if (!d || typeof d !== "object" || Array.isArray(d)) return json({success:false,error:"داتای ڕێکخستن دروست نییە."},400);
        const updates=[];
        if (d.currency!==undefined) updates.push(["currency",d.currency==="USD"?"USD":"IQD"]);
        if (d.usdRate!==undefined) {
          const usdRate=Number(d.usdRate);
          if (!Number.isFinite(usdRate) || usdRate < 1 || usdRate > 1000000000) return json({success:false,error:"نرخی گۆڕینی دۆلار دەبێت لە ١ تا ١,٠٠٠,٠٠٠,٠٠٠ بێت."},400);
          updates.push(["usdRate",usdRate]);
        }
        if (d.returnDays!==undefined) {
          const returnDays=Number(d.returnDays);
          if (!Number.isInteger(returnDays) || returnDays < 0 || returnDays > 3650) return json({success:false,error:"ماوەی مرجوعات دەبێت ژمارەیەکی تەواو لە ٠ تا ٣٦٥٠ ڕۆژ بێت."},400);
          updates.push(["returnDays",returnDays]);
        }
        if (d.openingCash!==undefined) {
          const openingCash=Number(d.openingCash);
          if (!Number.isFinite(openingCash) || openingCash < 0 || openingCash > 1e15) return json({success:false,error:"بڕی پارەی سەرەتایی سندوق دروست نییە."},400);
          updates.push(["openingCash",openingCash]);
        }
        if (d.dailySalesTarget!==undefined) {
          const dailySalesTarget=Number(d.dailySalesTarget);
          if (!Number.isFinite(dailySalesTarget) || dailySalesTarget < 1 || dailySalesTarget > 1e12) return json({success:false,error:"ئامانجی فرۆشتنی ڕۆژانە دروست نییە."},400);
          updates.push(["dailySalesTarget",dailySalesTarget]);
        }
        if (d.targetGrossMargin!==undefined) {
          const targetGrossMargin=Number(d.targetGrossMargin);
          if (!Number.isFinite(targetGrossMargin) || targetGrossMargin < 1 || targetGrossMargin > 95) return json({success:false,error:"ئامانجی قازانجی خام دەبێت لە ١ تا ٩٥ بێت."},400);
          updates.push(["targetGrossMargin",targetGrossMargin]);
        }
        // Validate every submitted value before persisting any of them.
        for (const [key,value] of updates) await megaSet(env.DB,key,value);
        return json({success:true});
      }

      if (path === "/api/mega/users" && request.method === "GET") {
        const a=await altinRequire(env.DB,request,"users.view"); if(a.error) return altinAuthResponse(json,a);
        const rows=await env.DB.prepare("SELECT id,username,name,role,permissions,active,date FROM altin_users ORDER BY username").all();
        return json({success:true,users:(rows.results||[]).map(x=>({...x,permissions:altinRolePerms(x),roleLabel:ALTIN_ROLE_LABELS[x.role]||x.role}))});
      }
      if (path === "/api/mega/users" && request.method === "POST") {
        const a=await altinRequire(env.DB,request,"users.manage"); if(a.error) return altinAuthResponse(json,a);
        if(a.user.role !== 'admin') return json({success:false,error:'تەنها ئەدمین دەتوانێت بەکارهێنەران دروست بکات یان دەستکارییان بکات.'},403);
        const d=await request.json(); const username=String(d.username||'').trim(); const password=String(d.password||'');
        if(!username||!password) return json({error:'username و password پێویستن'},400);
        const role=['admin','manager','cashier','seller','warehouse','accountant'].includes(d.role)?d.role:'cashier';
        try { const perms=Array.isArray(d.permissions)&&d.permissions.length?d.permissions:(ALTIN_PERMS[role]||[]); const id=d.id||crypto.randomUUID();
          await env.DB.prepare(`INSERT INTO altin_users(id,username,name,role,password,permissions,active,date) VALUES(?,?,?,?,?,?,?,?)`).bind(id,username,d.name||username,role,await altinPasswordHash(password),JSON.stringify(perms),d.active===false?0:1,new Date().toISOString()).run();
          return json({success:true,id});
        } catch(e){ return json({error:'ئەم username ـە پێشتر بەکارهاتووە'},409); }
      }
      if (path.startsWith("/api/mega/users/") && request.method === "PUT") {
        const a=await altinRequire(env.DB,request,"users.manage"); if(a.error) return altinAuthResponse(json,a);
        if(a.user.role !== 'admin') return json({success:false,error:'تەنها ئەدمین دەتوانێت بەکارهێنەران دروست بکات یان دەستکارییان بکات.'},403);
        const id=decodeURIComponent(path.split('/').pop()); const d=await request.json();
        const old=await env.DB.prepare('SELECT * FROM altin_users WHERE id=?').bind(id).first(); if(!old)return json({error:'بەکارهێنەر نەدۆزرایەوە'},404);
        const role=['admin','manager','cashier','seller','warehouse','accountant'].includes(d.role)?d.role:old.role;
        const perms=Array.isArray(d.permissions)&&d.permissions.length?d.permissions:(ALTIN_PERMS[role]||[]);
        const pw=d.password?await altinPasswordHash(String(d.password)):old.password;
        await env.DB.prepare(`UPDATE altin_users SET username=?,name=?,role=?,password=?,permissions=?,active=? WHERE id=?`).bind(d.username??old.username,d.name??old.name,role,pw,JSON.stringify(perms),d.active===false?0:1,id).run();
        return json({success:true,id});
      }
      if (path.startsWith("/api/mega/users/") && request.method === "DELETE") {
        const a=await altinRequire(env.DB,request,"users.manage"); if(a.error) return altinAuthResponse(json,a);
        if(a.user.role !== 'admin') return json({success:false,error:'تەنها ئەدمین دەتوانێت بەکارهێنەران دروست بکات یان دەستکارییان بکات.'},403);
        const id=decodeURIComponent(path.split('/').pop()); const old=await env.DB.prepare('SELECT username FROM altin_users WHERE id=?').bind(id).first();
        if(!old)return json({error:'بەکارهێنەر نەدۆزرایەوە'},404); if(old.username==='admin')return json({error:'Admin ـی سەرەکی ناتوانرێت بسڕدرێتەوە'},400);
        await env.DB.prepare('DELETE FROM altin_users WHERE id=?').bind(id).run(); await env.DB.prepare('DELETE FROM altin_sessions WHERE user_id=?').bind(id).run(); return json({success:true});
      }

      /* ================= PURCHASE DEBT ADJUSTMENT ================= */
      if (path === "/api/purchase-debts/adjust" && request.method === "POST") {
        const auth = await altinRequire(env.DB, request, "purchases.edit");
        if (auth.error) return altinAuthResponse(json, auth);
        const data = await request.json();
        const debtId = String(data.debtId || "").trim();
        const operation = data.operation === "increase" ? "increase" : data.operation === "decrease" ? "decrease" : "";
        const amount = Number(data.amount);
        if (!debtId || !operation || !Number.isFinite(amount) || amount <= 0) return json({success:false,error:"Invalid debt adjustment"},400);
        const currency = data.currency === "USD" ? "USD" : "IQD";
        const old = await env.DB.prepare("SELECT * FROM debts WHERE id=?").bind(debtId).first();
        if (!old && operation === "decrease") return json({success:false,error:"Debt not found or already settled"},404);
        if (old && (old.currency || "IQD") !== currency) return json({success:false,error:"Currency mismatch"},400);
        const current = Number(old?.amount || 0);
        if (operation === "decrease" && amount > current) return json({success:false,error:"Adjustment exceeds remaining debt"},400);
        const next = operation === "increase" ? current + amount : current - amount;
        const name = String(data.name || old?.name || "فرۆشیاری نەناسراو").slice(0,120);
        const date = data.date || new Date().toISOString();
        const note = String(data.note || "").slice(0,500);
        const statements = [];
        if (next <= 0) {
          statements.push(env.DB.prepare("DELETE FROM debts WHERE id=?").bind(debtId));
        } else if (old) {
          statements.push(env.DB.prepare("UPDATE debts SET amount=?,name=?,date=? WHERE id=?").bind(next,name,date,debtId));
        } else {
          statements.push(env.DB.prepare("INSERT INTO debts (id,name,amount,note,date,currency) VALUES (?,?,?,?,?,?)").bind(debtId,name,next,"قەرزی کڕین • قەرزی دووبارە زیادکرا",date,currency));
        }
        statements.push(env.DB.prepare("INSERT INTO audit_logs (id,date,action,entity,entityId,details,actor) VALUES (?,?,?,?,?,?,?)").bind(crypto.randomUUID(),date,"ADJUST_PURCHASE_DEBT","debt",debtId,JSON.stringify({operation,amount,currency,name,note,previousAmount:current,newAmount:Math.max(0,next)}),auth.user.username));
        await env.DB.batch(statements);
        return json({success:true,debtId,previousAmount:current,amount:Math.max(0,next),currency});
      }

      /* ================= SUPPLIER-WIDE PURCHASE DEBT PAYMENT ================= */
      if (path === "/api/purchase-debts/pay-supplier" && request.method === "POST") {
        const auth = await altinRequire(env.DB, request, "purchases.view");
        if (auth.error) return altinAuthResponse(json, auth);
        let data = {};
        try { data = await request.json(); } catch { return json({success:false,error:"داتای پارەدانی گشتی دروست نییە."},400); }
        const supplier = String(data.supplier || "").trim();
        const supplierKey = supplier.trim().replace(/\s+/g, " ").toLocaleLowerCase();
        const currency = data.currency === "USD" ? "USD" : "IQD";
        const amount = Number(data.amount);
        const paymentMethod = String(data.paymentMethod || "نەقد").trim().slice(0,80);
        const paymentDate = String(data.date || new Date().toISOString());
        if (!supplier || supplier.length > 120 || !Number.isFinite(amount) || amount <= 0 || amount > 1e12 || !paymentMethod) {
          return json({success:false,error:"ناوی فرۆشیار، بڕی پارە، یان شێوازی پارەدان دروست نییە."},400);
        }
        if (!Number.isFinite(Date.parse(paymentDate))) return json({success:false,error:"بەرواری پارەدان دروست نییە."},400);

        const debtRows = await env.DB.prepare("SELECT id,name,amount,note,date,currency FROM debts WHERE amount > 0 ORDER BY date ASC, rowid ASC").all();
        const eligible = (debtRows.results || []).filter(d => {
          const isPurchaseDebt = String(d.id || "").startsWith("purchase-") || String(d.note || "").includes("قەرزی کڕین");
          const nameKey = String(d.name || "").trim().replace(/\s+/g, " ").toLocaleLowerCase();
          const rowCurrency = String(d.currency || "IQD").toUpperCase() === "USD" ? "USD" : "IQD";
          return isPurchaseDebt && nameKey === supplierKey && rowCurrency === currency && Number(d.amount || 0) > 0;
        });
        const totalRemaining = eligible.reduce((sum,d) => sum + Math.max(0,Number(d.amount || 0)),0);
        if (!eligible.length || totalRemaining <= 0) return json({success:false,error:"بۆ ئەم فرۆشیارە لەم دراوەدا قەرزی ماوە نەدۆزرایەوە."},404);
        if (amount > totalRemaining + 1e-8) return json({success:false,error:"بڕی پارەدان لە کۆی قەرزی ماوە زیاترە.",remaining:totalRemaining,currency},400);

        let left = amount;
        let allocations = 0;
        const statements = [];
        for (const d of eligible) {
          if (left <= 1e-8) break;
          const current = Math.max(0,Number(d.amount || 0));
          if (current <= 0) continue;
          const paid = Math.min(current,left);
          const next = Math.max(0,current-paid);
          const paymentId = crypto.randomUUID();
          const paymentNote = (`قەرزی کڕین • پارەدانی گشتی بۆ فرۆشیار: ${supplier} • ${String(data.note || "پارەدانی قەرزی کڕین").slice(0,220)}`).slice(0,500);
          statements.push(env.DB.prepare(`INSERT INTO payments(id,debtId,customer,amount,currency,note,date,paymentMethod) VALUES(?,?,?,?,?,?,?,?)`).bind(
            paymentId,d.id,String(d.name || supplier),paid,currency,paymentNote,paymentDate,paymentMethod
          ));
          if (next <= 1e-8) statements.push(env.DB.prepare("DELETE FROM debts WHERE id=? AND amount=?").bind(d.id,current));
          else statements.push(env.DB.prepare("UPDATE debts SET amount=? WHERE id=? AND amount=?").bind(next,d.id,current));
          altinAppendChangeGuard(statements,env.DB);
          statements.push(env.DB.prepare("INSERT INTO audit_logs(id,date,action,entity,entityId,details,actor) VALUES(?,?,?,?,?,?,?)").bind(
            crypto.randomUUID(),new Date().toISOString(),"PAYMENT","debt",d.id,
            JSON.stringify({paid,remaining:next,customer:d.name||supplier,supplier,currency,paymentMethod,aggregatePayment:true,requestedAmount:amount}),
            auth.user.username
          ));
          left = Math.max(0,left-paid);
          allocations += 1;
        }
        const conflict = await altinBatchOrConflict(env.DB,statements,json);
        if (conflict) return conflict;
        return json({success:true,supplier,currency,paid:amount,remaining:Math.max(0,totalRemaining-amount),allocations,paymentMethod});
      }

      /* ================= CUSTOMER DEBT ADJUSTMENT ================= */
      if (path === "/api/customer-debts/adjust" && request.method === "POST") {
        const auth = await altinRequire(env.DB, request, "debts.edit");
        if (auth.error) return altinAuthResponse(json, auth);
        let data = {};
        try { data = await request.json(); } catch { return json({success:false,error:"داتای دەستکاری قەرز دروست نییە."},400); }
        const debtId = String(data.id || "").trim();
        const operation = ["increase","decrease","set"].includes(data.operation) ? data.operation : "";
        const amount = Number(data.amount);
        if (!debtId || !operation || !Number.isFinite(amount) || amount < 0 || amount > 1000000000000 || (operation !== "set" && amount <= 0)) {
          return json({success:false,error:"بڕی قەرز یان جۆری گۆڕانکاری دروست نییە."},400);
        }
        const old = await env.DB.prepare("SELECT * FROM debts WHERE id=?").bind(debtId).first();
        if (!old) return json({success:false,error:"قەرزەکە نەدۆزرایەوە."},404);
        if (String(old.id || "").startsWith("purchase-") || String(old.note || "").includes("قەرزی کڕین")) {
          return json({success:false,error:"قەرزی فرۆشیار لەم endpoint ـە دەستکاری ناکرێت؛ بەشی قەرزی کڕین بەکاربهێنە."},400);
        }
        const current = Math.max(0, Number(old.amount || 0));
        if (operation === "decrease" && amount > current) return json({success:false,error:"بڕی کەمکردن لە قەرزی ماوە زیاترە."},400);
        const next = operation === "increase" ? current + amount : operation === "decrease" ? current - amount : amount;
        if (!Number.isFinite(next) || next < 0) return json({success:false,error:"قەرزی نوێ دروست نییە."},400);
        const name = operation === "set" && data.name !== undefined ? String(data.name || "").trim().slice(0,120) : String(old.name || "").trim();
        if (!name) return json({success:false,error:"ناوی کڕیار پێویستە."},400);
        let note = operation === "set" && data.note !== undefined ? String(data.note || "").slice(0,450) : String(old.note || "");
        // Preserve invoice linkage tags so invoice balances keep tracking this debt.
        const invoiceMarkers = [...String(old.note || "").matchAll(/\[فاکتۆر:[^\]]+\]/g)].map(m => m[0]);
        for (const marker of invoiceMarkers) if (!note.includes(marker)) note = (note ? note + " " : "") + marker;
        const date = operation === "set" && data.date ? String(data.date).slice(0,40) : String(old.date || new Date().toISOString());
        const currency = old.currency === "USD" ? "USD" : "IQD";
        const now = new Date().toISOString();
        const statements = [
          env.DB.prepare("UPDATE debts SET name=?,amount=?,note=?,date=? WHERE id=?").bind(name, Math.max(0,next), note, date, debtId)
        ];
        // If this debt belongs to an invoice, keep the invoice customer name aligned with the ledger.
        for (const marker of invoiceMarkers) {
          const saleId = marker.slice("[فاکتۆر:".length, -1).trim();
          if (saleId) statements.push(env.DB.prepare("UPDATE sales SET customer=? WHERE id=?").bind(name, saleId));
        }
        statements.push(env.DB.prepare("INSERT INTO audit_logs (id,date,action,entity,entityId,details,actor) VALUES (?,?,?,?,?,?,?)").bind(
          crypto.randomUUID(), now, operation === "set" ? "EDIT_CUSTOMER_DEBT" : "ADJUST_CUSTOMER_DEBT", "debt", debtId,
          JSON.stringify({operation,adjustment:amount,previousAmount:current,newAmount:Math.max(0,next),name,currency,note}), auth.user.username
        ));
        await env.DB.batch(statements);
        return json({success:true,id:debtId,operation,previousAmount:current,amount:Math.max(0,next),currency});
      }

      /* ================= BULK PRODUCT PROFIT MARGIN ================= */
      if (path === "/api/products/bulk-price" && request.method === "POST") {
        const auth = await altinRequire(env.DB, request, "stock.edit");
        if (auth.error) return altinAuthResponse(json, auth);
        let data = {};
        try { data = await request.json(); } catch { return json({success:false,error:"داتای ڕێژەی قازانج دروست نییە."},400); }
        const ids = Array.from(new Set((Array.isArray(data.ids) ? data.ids : []).map(x => String(x || "").trim()).filter(Boolean)));
        const percent = Number(data.percent);
        if (!ids.length) return json({success:false,error:"لانیکەم یەک کاڵا هەڵبژێرە."},400);
        if (ids.length > 200) return json({success:false,error:"لە هەر جارێکدا تەنها تا ٢٠٠ کاڵا هەڵبژێرە."},400);
        if (!Number.isFinite(percent) || percent <= 0 || percent > 1000) return json({success:false,error:"ڕێژەی قازانج دەبێت لە ٠.٠١٪ تا ١٠٠٠٪ بێت."},400);

        const changes = [];
        for (const id of ids) {
          const p = await env.DB.prepare("SELECT id,name,buy,sell FROM products WHERE id=?").bind(id).first();
          if (!p) return json({success:false,error:`کاڵای هەڵبژێردراو (${id}) لە کۆگا نەدۆزرایەوە.`},404);
          const buy = Number(p.buy);
          if (!Number.isFinite(buy) || buy <= 0) return json({success:false,error:`نرخی کڕینی کاڵای «${String(p.name || id)}» دیاری نەکراوە؛ تکایە سەرەتا نرخی کڕینی دروست بنووسە.`},400);
          const before = Math.max(0, num(p.sell));
          const sell = Math.round(buy * (1 + percent / 100));
          changes.push({id:String(p.id),name:String(p.name || ""),buy,before,sell,profitPercent:percent});
        }

        const now = new Date().toISOString();
        const statements = changes.map(p => env.DB.prepare("UPDATE products SET sell=? WHERE id=?").bind(p.sell,p.id));
        statements.push(env.DB.prepare("INSERT INTO audit_logs (id,date,action,entity,entityId,details,actor) VALUES (?,?,?,?,?,?,?)").bind(
          crypto.randomUUID(), now, "BULK_PROFIT_PRICE_UPDATE", "products", "bulk-price",
          JSON.stringify({mode:"profit-on-buy-price",percent,updated:changes.length,changes:changes.map(p=>({id:p.id,name:p.name,buy:p.buy,before:p.before,sell:p.sell,profitPercent:p.profitPercent}))}),
          auth.user.username
        ));
        await env.DB.batch(statements);
        return json({success:true,updated:changes.length,mode:"profit-on-buy-price",percent,products:changes.map(p=>({id:p.id,buy:p.buy,sell:p.sell,profitPercent:p.profitPercent}))});
      }

      /* ================= SAFE BARCODE-ONLY UPDATE ================= */
      const barcodeMatch = path.match(/^\/api\/products\/([^/]+)\/barcode$/);
      if (barcodeMatch && request.method === "PUT") {
        const auth = await altinRequire(env.DB, request, "stock.edit");
        if (auth.error) return altinAuthResponse(json, auth);
        let data = {};
        try { data = await request.json(); } catch { return json({success:false,error:"داتای بارکۆد دروست نییە."},400); }
        const code = String(data.code || "").trim();
        if (!code || code.length > 120) return json({success:false,error:"کۆدی بارکۆد دەبێت ١٢٠ پیت یان کەمتر بێت و بەتاڵ نەبێت."},400);
        let productId;
        try { productId = decodeURIComponent(barcodeMatch[1]); } catch { return json({success:false,error:"ناسنامەی کاڵا دروست نییە."},400); }
        const product = await env.DB.prepare("SELECT id FROM products WHERE id=?").bind(productId).first();
        if (!product) return json({success:false,error:"کاڵاکە نەدۆزرایەوە."},404);
        const duplicate = await env.DB.prepare("SELECT id FROM products WHERE LOWER(TRIM(code))=LOWER(TRIM(?)) AND id<>? LIMIT 1").bind(code,productId).first();
        if (duplicate) return json({success:false,error:"ئەم کۆدی بارکۆدە پێشتر بۆ کاڵایەکی تر بەکارهاتووە."},409);
        await env.DB.batch([
          env.DB.prepare("UPDATE products SET code=? WHERE id=?").bind(code,productId),
          env.DB.prepare("INSERT INTO audit_logs(id,date,action,entity,entityId,details,actor) VALUES(?,?,?,?,?,?,?)")
            .bind(crypto.randomUUID(),new Date().toISOString(),"BARCODE_CHANGE","product",productId,JSON.stringify({code}),auth.user.username)
        ]);
        return json({success:true,id:productId,code});
      }

      /* ================= SAFE SELL-PRICE UPDATE ================= */
      const sellPriceMatch = path.match(/^\/api\/products\/([^/]+)\/sell-price$/);
      if (sellPriceMatch && request.method === "PUT") {
        const auth = await altinRequire(env.DB, request, "sales.create");
        if (auth.error) return altinAuthResponse(json, auth);
        let data = {};
        try { data = await request.json(); } catch { return json({success:false,error:"نرخی نوێ دروست نییە."},400); }
        const sell = Number(data.sell);
        if (!Number.isFinite(sell) || sell < 0 || sell > 1000000000000) return json({success:false,error:"نرخی فرۆشتن دروست نییە."},400);
        let productId;
        try { productId = decodeURIComponent(sellPriceMatch[1]); } catch { return json({success:false,error:"ناسنامەی کاڵا دروست نییە."},400); }
        const product = await env.DB.prepare("SELECT id FROM products WHERE id=?").bind(productId).first();
        if (!product) return json({success:false,error:"کاڵاکە نەدۆزرایەوە."},404);
        await env.DB.batch([
          env.DB.prepare("UPDATE products SET sell=? WHERE id=?").bind(sell, productId),
          env.DB.prepare("INSERT INTO audit_logs(id,date,action,entity,entityId,details,actor) VALUES(?,?,?,?,?,?,?)")
            .bind(crypto.randomUUID(),new Date().toISOString(),"SELL_PRICE_CHANGE","product",productId,JSON.stringify({sell}),auth.user.username)
        ]);
        return json({success:true,id:productId,sell});
      }

      /* ================= STANDARD API ================= */

      const parts = path.split("/").filter(Boolean);
      const table = parts[1];
      const id = parts[2];

      if (!allowed.has(table)) {
        return json(
          { error: "Invalid endpoint" },
          400
        );
      }

      const methodPerm = {
        GET: `${table}.view`, POST: `${table}.create`, PUT: `${table}.edit`, DELETE: `${table}.delete`
      };
      const permTable = (table === 'stock-movements' || table === 'products') ? 'stock' : table;
      let requiredPerm = methodPerm[request.method];
      if (requiredPerm) requiredPerm = requiredPerm.replace(table,permTable);
      if (table === 'audit' && request.method === 'POST') requiredPerm = 'audit.view';
      const authz = await altinRequire(env.DB,request,requiredPerm);
      if(authz.error) return altinAuthResponse(json,authz);
      const actor = authz.user.username;

      /* ================= POST ================= */

      if (request.method === "POST") {
        const data = await request.json();
        data.actor = actor;

        if (!data.id) {
          data.id = uid();
        }

        if (table === "products") {
          const productCode = String(data.code || "").trim();
          if (productCode) {
            const duplicate = await env.DB.prepare("SELECT id FROM products WHERE LOWER(TRIM(code))=LOWER(TRIM(?)) LIMIT 1").bind(productCode).first();
            if (duplicate) return json({success:false,error:"ئەم کۆدە پێشتر بۆ کاڵایەکی تر بەکارهاتووە."},409);
          }
          await env.DB
            .prepare(
              `INSERT INTO products
              (id,name,code,buy,sell,qty,min)
              VALUES (?,?,?,?,?,?,?)`
            )
            .bind(
              data.id,
              String(data.name || "").trim(),
              productCode,
              num(data.buy),
              num(data.sell),
              num(data.qty),
              num(data.min)
            )
            .run();

          return json({
            success: true,
            id: data.id
          });
        }

        if (table === "sales") {
          return saleTransaction(
            data,
            env.DB,
            json
          );
        }

        if (table === "purchases") {
          return purchaseTransaction(
            data,
            env.DB,
            json
          );
        }

        if (table === "expenses") {
          await env.DB
            .prepare(
              `INSERT INTO expenses
              (id,name,amount,date)
              VALUES (?,?,?,?)`
            )
            .bind(
              data.id,
              data.name || "",
              num(data.amount),
              data.date || new Date().toISOString()
            )
            .run();

          return json({
            success: true,
            id: data.id
          });
        }

        if (table === "debts") {
          await env.DB
            .prepare(
              `INSERT INTO debts
              (id,name,amount,note,date,currency)
              VALUES (?,?,?,?,?,?)`
            )
            .bind(
              data.id,
              data.name || "",
              num(data.amount),
              data.note || "",
              data.date || new Date().toISOString(),
              data.currency === "USD" ? "USD" : "IQD"
            )
            .run();

          return json({
            success: true,
            id: data.id
          });
        }

        if (table === "returns") {
          return returnTransaction(
            data,
            env.DB,
            json
          );
        }

        if (table === "audit") {
          return auditInsert(
            data,
            env.DB,
            json
          );
        }

        return json(
          { error: "Unsupported POST" },
          400
        );
      }

      /* ================= PUT ================= */

      if (request.method === "PUT") {
        if (!id) {
          return json(
            { error: "Missing id" },
            400
          );
        }

        const data = await request.json();

        /* -------- PRODUCT (optimistic stock edit) -------- */
        if (table === "products") {
          if (data.expectedQty === undefined || !Number.isFinite(Number(data.expectedQty))) {
            return json({success:false,error:"داتا کۆگا کۆنە یان پشکنینی ژمارەی پێشوو نییە. داتا نوێ بکەرەوە و دووبارە هەوڵ بدەرەوە."},400);
          }
          const expectedQty = Number(data.expectedQty);
          const nextQty = num(data.qty, expectedQty);
          const productCode = String(data.code || "").trim();
          if (expectedQty < 0 || nextQty < 0 || nextQty > 1e12) return json({success:false,error:"ژمارەی کۆگا دروست نییە."},400);
          if (productCode) {
            const duplicate = await env.DB.prepare("SELECT id FROM products WHERE LOWER(TRIM(code))=LOWER(TRIM(?)) AND id<>? LIMIT 1").bind(productCode,id).first();
            if (duplicate) return json({success:false,error:"ئەم کۆدە پێشتر بۆ کاڵایەکی تر بەکارهاتووە."},409);
          }
          const now = new Date().toISOString();
          const statements = [env.DB.prepare(
            `UPDATE products SET name=?,code=?,buy=?,sell=?,qty=?,min=? WHERE id=? AND qty=?`
          ).bind(String(data.name || "").trim(),productCode,num(data.buy),num(data.sell),nextQty,num(data.min),id,expectedQty)];
          altinAppendChangeGuard(statements,env.DB);
          if (Math.abs(nextQty-expectedQty)>1e-8) {
            statements.push(env.DB.prepare("INSERT INTO stock_movements(id,date,productId,type,qty,beforeQty,afterQty,refId,note) VALUES(?,?,?,?,?,?,?,?,?)")
              .bind(crypto.randomUUID(),now,id,"manual-adjustment",nextQty-expectedQty,expectedQty,nextQty,id,"دەستکاریی دەستیی کۆگا"));
          }
          statements.push(env.DB.prepare("INSERT INTO audit_logs(id,date,action,entity,entityId,details,actor) VALUES(?,?,?,?,?,?,?)")
            .bind(crypto.randomUUID(),now,"EDIT_PRODUCT","product",id,JSON.stringify({name:String(data.name||"").trim(),code:String(data.code||""),buy:num(data.buy),sell:num(data.sell),beforeQty:expectedQty,afterQty:nextQty,min:num(data.min)}),actor));
          const conflict = await altinBatchOrConflict(env.DB,statements,json);
          if (conflict) return conflict;
          return json({success:true,id});
        }

        /* -------- SALE -------- */

        if (table === "sales") {
          data.id = id;
          data.actor = actor;
          return editSaleTransaction(data, env.DB, json);
        }

        /* -------- PURCHASE -------- */

        if (table === "purchases") {
          data.id = id;
          data.actor = actor;
          return editPurchaseTransaction(data, env.DB, json);
        }

        /* -------- EXPENSE -------- */

        if (table === "expenses") {
          await env.DB
            .prepare(
              `UPDATE expenses
               SET name=?,
                   amount=?,
                   date=?
               WHERE id=?`
            )
            .bind(
              data.name || "",
              num(data.amount),
              data.date ||
                new Date().toISOString(),
              id
            )
            .run();

          return json({
            success: true,
            id
          });
        }

        /* -------- DEBT -------- */

        if (table === "debts") {
          await env.DB
            .prepare(
              `UPDATE debts
               SET name=?,
                   amount=?,
                   note=?,
                   date=?,
                   currency=?
               WHERE id=?`
            )
            .bind(
              data.name || "",
              num(data.amount),
              data.note || "",
              data.date ||
                new Date().toISOString(),
              data.currency === "USD" ? "USD" : "IQD",
              id
            )
            .run();

          return json({
            success: true,
            id
          });
        }

        return json(
          { error: "Unsupported PUT" },
          400
        );
      }

      /* ================= DELETE ================= */

      if (request.method === "DELETE") {
        if (!id) return json({error:"Missing id"},400);
        if (table === "products" && id === "all") {
          // This destructive action is intentionally admin-only.
          if (authz.user.role !== 'admin') return json({success:false,error:'تەنها بەڕێوەبەری گشتی دەتوانێت هەموو کاڵاکان بسڕێتەوە.'},403);
          await env.DB.batch([
            env.DB.prepare("DELETE FROM products"),
            env.DB.prepare("INSERT INTO audit_logs(id,date,action,entity,entityId,details,actor) VALUES(?,?,?,?,?,?,?)")
              .bind(crypto.randomUUID(),new Date().toISOString(),'DELETE_ALL','products','all','{}',actor)
          ]);
          return json({success:true});
        }
        return await altinDeleteRecord(table,id,env.DB,actor,json);
      }

      return json(
        { error: "Method not allowed" },
        405
      );

    } catch (err) {
      const requestId = crypto.randomUUID();
      console.error('ALTIN API request failed', {
        requestId,
        method: request.method,
        path,
        message: String(err?.message || err || 'Unknown error')
      });
      return json(
        {success:false,error:'هەڵەی ناوخۆیی سێرڤەر ڕوویدا.',requestId},
        500
      );
    }
  }
};


/* =========================================================
   HELPERS
========================================================= */

function parseItems(rows) {
  return (rows.results || []).map(x => {
    if (typeof x.items === "string") {
      try {
        x.items = JSON.parse(x.items);
      } catch {
        x.items = [];
      }
    }

    return x;
  });
}


/* =========================================================
   DATABASE SCHEMA
========================================================= */

async function ensureSchema(db) {

  // Initialize core tables on a fresh D1 database; existing rows are preserved.
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', code TEXT DEFAULT '',
      buy REAL DEFAULT 0, sell REAL DEFAULT 0, qty REAL DEFAULT 0, min REAL DEFAULT 0
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS sales (
      id TEXT PRIMARY KEY, date TEXT NOT NULL, items TEXT DEFAULT '[]', total REAL DEFAULT 0,
      customer TEXT DEFAULT '', customerPhone TEXT DEFAULT '', paymentType TEXT DEFAULT 'cash',
      previousDebt REAL DEFAULT 0, reason TEXT DEFAULT '', subtotal REAL DEFAULT 0,
      discount REAL DEFAULT 0, paidAmount REAL DEFAULT 0, debtAmount REAL DEFAULT 0
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS purchases (
      id TEXT PRIMARY KEY, product TEXT, qty REAL DEFAULT 0, price REAL DEFAULT 0,
      supplier TEXT DEFAULT '', date TEXT NOT NULL, paymentType TEXT DEFAULT 'cash',
      paidAmount REAL DEFAULT 0, debtAmount REAL DEFAULT 0, total REAL DEFAULT 0, currency TEXT DEFAULT 'IQD'
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS expenses (
      id TEXT PRIMARY KEY, name TEXT DEFAULT '', amount REAL DEFAULT 0, date TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS debts (
      id TEXT PRIMARY KEY, name TEXT DEFAULT '', amount REAL DEFAULT 0, note TEXT DEFAULT '',
      date TEXT NOT NULL, currency TEXT DEFAULT 'IQD'
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS returns (
      id TEXT PRIMARY KEY, date TEXT NOT NULL, items TEXT DEFAULT '[]', total REAL DEFAULT 0,
      customer TEXT DEFAULT '', reason TEXT DEFAULT ''
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS altin_tx_guard (ok INTEGER NOT NULL CHECK(ok=1))`)
  ]);

  const addCols = [];

  const salesCols =
    await db
      .prepare(
        "PRAGMA table_info(sales)"
      )
      .all();

  const have =
    new Set(
      (salesCols.results || [])
        .map(x => x.name)
    );

  for (
    const [
      name,
      type,
      def
    ] of [
      ["subtotal", "REAL", "0"],
      ["discount", "REAL", "0"],
      ["paidAmount", "REAL", "0"],
      ["debtAmount", "REAL", "0"]
    ]
  ) {
    if (!have.has(name)) {
      addCols.push(
        db.prepare(
          `ALTER TABLE sales
           ADD COLUMN ${name}
           ${type}
           DEFAULT ${def}`
        )
      );
    }
  }

  if (addCols.length) {
    await db.batch(addCols);
  }

  await db.batch([

    db.prepare(`
      CREATE TABLE IF NOT EXISTS payments (
        id TEXT PRIMARY KEY,
        debtId TEXT,
        customer TEXT,
        amount REAL NOT NULL,
        currency TEXT DEFAULT 'IQD',
        note TEXT DEFAULT '',
        date TEXT NOT NULL
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        date TEXT NOT NULL,
        action TEXT,
        entity TEXT,
        entityId TEXT,
        details TEXT,
        actor TEXT
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS stock_movements (
        id TEXT PRIMARY KEY,
        date TEXT NOT NULL,
        productId TEXT,
        type TEXT,
        qty REAL,
        beforeQty REAL,
        afterQty REAL,
        refId TEXT,
        note TEXT
      )
    `)

  ]);
}


/* =========================================================
   SALE TRANSACTION
========================================================= */

async function saleTransaction(
  s,
  db,
  json
) {

  if (
    !s?.id ||
    !Array.isArray(s.items) ||
    !s.items.length
  ) {
    return json(
      { error: "Invalid sale" },
      400
    );
  }

  let items =
    s.items.map(x => ({
      ...x,
      qty: Number(x.qty),
      price: Number(x.price)
    }));

  if (
    items.some(
      x =>
        !(x.qty > 0) ||
        !Number.isFinite(x.qty) ||
        !Number.isFinite(x.price) ||
        x.price < 0
    )
  ) {
    return json(
      {
        error:
          "Invalid item quantity or price"
      },
      400
    );
  }

  const subtotal =
    items.reduce(
      (sum, x) =>
        sum +
        x.qty *
        x.price,
      0
    );

  const discount =
    Math.min(
      Math.max(
        Number(s.discount) || 0,
        0
      ),
      subtotal
    );

  const total =
    Math.max(
      0,
      subtotal - discount
    );

  const requestedPaymentType = ["cash", "credit", "partial"].includes(String(s.paymentType || "cash"))
    ? String(s.paymentType || "cash")
    : "cash";
  // A cash sale is always fully paid. For credit/partial sales, only the actual
  // amount received is counted as cash, and the remainder becomes customer debt.
  const requestedPaid = Math.max(0, Number(s.paidAmount) || 0);
  const paid = requestedPaymentType === "cash"
    ? total
    : Math.min(requestedPaid, total);
  const debt = Math.max(0, total - paid);
  const paymentType = debt > 0 ? (paid > 0 ? "partial" : "credit") : "cash";

  const grouped =
    new Map();

  for (const x of items) {
    if (
      !x.manual &&
      x.product
    ) {
      grouped.set(
        x.product,
        (
          grouped.get(x.product) ||
          0
        ) + x.qty
      );
    }
  }

  const ids =
    [...grouped.keys()];

  const products = [];

  for (const productId of ids) {

    const p =
      await db
        .prepare(
          "SELECT * FROM products WHERE id=?"
        )
        .bind(productId)
        .first();

    if (!p) {
      return json(
        {
          error:
            `Product ${productId} not found`
        },
        400
      );
    }

    products.push(p);
  }

  for (const p of products) {

    const q =
      grouped.get(p.id);

    if (
      Number(p.qty) < q
    ) {
      return json(
        {
          error:
            `کۆگای ${p.name} بەشی پێویست نییە`
        },
        409
      );
    }
  }

  // Save a cost-price snapshot on every sold line. Future changes to the stock
  // purchase price will therefore not rewrite the profit of past invoices.
  const productById = new Map(products.map(p => [String(p.id), p]));
  items = items.map(item => {
    const p = !item.manual && item.product ? productById.get(String(item.product)) : null;
    return {
      ...item,
      costPrice: p ? Math.max(0, Number(p.buy || 0)) : Math.max(0, Number(item.costPrice || 0))
    };
  });

  const customer = String(s.customer || "").trim();
  if (debt > 0 && !customer) return json({error:"بۆ فرۆشتنی قەرز ناوی کڕیار پێویستە."},400);
  const previousDebtRow = customer
    ? await db.prepare("SELECT COALESCE(SUM(amount),0) AS amount FROM debts WHERE LOWER(TRIM(name))=LOWER(TRIM(?)) AND id NOT LIKE 'purchase-%' AND COALESCE(note,'') NOT LIKE '%قەرزی کڕین%'")
        .bind(customer).first()
    : null;
  const previousDebt = Math.max(0, Number(previousDebtRow?.amount || 0));

  const statements = [];

  /*
   * کەمکردنەوەی کۆگا
   */

  for (const p of products) {

    const q =
      grouped.get(p.id);

    statements.push(
      db.prepare(
        `UPDATE products
         SET qty=qty-?
         WHERE id=?
         AND qty>=?`
      ).bind(
        q,
        p.id,
        q
      )
    );
    altinAppendChangeGuard(statements, db);

    statements.push(
      db.prepare(
        `INSERT INTO stock_movements
        (
          id,
          date,
          productId,
          type,
          qty,
          beforeQty,
          afterQty,
          refId,
          note
        )
        VALUES (?,?,?,?,?,?,?,?,?)`
      ).bind(
        crypto.randomUUID(),
        new Date().toISOString(),
        p.id,
        "sale",
        -q,
        p.qty,
        p.qty - q,
        s.id,
        "فرۆشتن"
      )
    );

  }


  /*
   * ⭐ گرنگ:
   * نرخی دەستکاری‌کراوی فرۆشتن
   * دەبێتە نرخی نوێی کۆگا
   */

  for (const item of items) {

    if (
      item.manual ||
      !item.product
    ) {
      continue;
    }

    const price =
      Number(item.price);

    if (
      !Number.isFinite(price) ||
      price < 0
    ) {
      continue;
    }

    statements.push(
      db.prepare(
        `UPDATE products
         SET sell=?
         WHERE id=?`
      ).bind(
        price,
        item.product
      )
    );
  }


  const canonicalReason =
    JSON.stringify({
      subtotal,
      discount,
      total,
      paidAmount: paid,
      debtAmount: debt
    });


  /*
   * پاشەکەوتکردنی فاکتۆر
   */

  statements.push(
    db.prepare(
      `INSERT INTO sales
      (
        id,
        date,
        items,
        total,
        customer,
        customerPhone,
        paymentType,
        previousDebt,
        reason,
        subtotal,
        discount,
        paidAmount,
        debtAmount
      )
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      s.id,
      s.date ||
        new Date().toISOString(),

      JSON.stringify(items),

      total,

      customer,

      s.customerPhone || "",

      paymentType,

      previousDebt,

      canonicalReason,

      subtotal,

      discount,

      paid,

      debt
    )
  );


  /*
   * قەرز
   */

  if (debt > 0) {

    statements.push(
      db.prepare(
        `INSERT INTO debts
        (
          id,
          name,
          amount,
          note,
          date
        )
        VALUES (?,?,?,?,?)`
      ).bind(
        crypto.randomUUID(),
        s.customer || "",
        debt,
        `قەرزی فاکتۆر - ${
          s.customerPhone || ""
        } [فاکتۆر:${s.id}]`,
        s.date ||
          new Date().toISOString()
      )
    );
  }


  /*
   * Audit
   */

  statements.push(
    db.prepare(
      `INSERT INTO audit_logs
      (
        id,
        date,
        action,
        entity,
        entityId,
        details,
        actor
      )
      VALUES (?,?,?,?,?,?,?)`
    ).bind(
      crypto.randomUUID(),
      new Date().toISOString(),
      "SALE",
      "sale",
      s.id,
      JSON.stringify({
        total,
        subtotal,
        discount,
        paidAmount: paid,
        customer: s.customer,
        debtAmount: debt
      }),
      s.actor || "system"
    )
  );


  const conflict = await altinBatchOrConflict(db, statements, json);
  if (conflict) return conflict;

  return json({
    success: true,
    id: s.id,
    priceSync: true
  });
}


/* =========================================================
   ATOMIC SALE EDIT
   Reconciles stock, sale totals and the linked customer debt in one D1 batch.
========================================================= */
async function editSaleTransaction(s, db, json) {
  const saleId = String(s?.id || '').trim();
  if (!saleId) return json({success:false,error:'ژمارەی فاکتۆر نەدراوە.'},400);
  const oldSale = await db.prepare('SELECT * FROM sales WHERE id=?').bind(saleId).first();
  if (!oldSale) return json({success:false,error:'فاکتۆرەکە نەدۆزرایەوە.'},404);
  if (!Array.isArray(s.items) || !s.items.length) return json({success:false,error:'لانیکەم یەک کاڵا پێویستە.'},400);

  // Read the original invoice before validating submitted products. A product may
  // have been removed from inventory after the sale; historical invoices must
  // still be editable without recreating stock records or losing the item label.
  let oldItems=[];
  try { oldItems = typeof oldSale.items === 'string' ? JSON.parse(oldSale.items || '[]') : (oldSale.items || []); } catch { oldItems=[]; }
  if (!Array.isArray(oldItems)) oldItems=[];
  // Editing an invoice after a linked return would need to re-price/reallocate that
  // return as well. Until the UI supports a joint edit, reject it rather than
  // silently reopening debt or rewriting stock/accounting history.
  const returnRowsForSaleEdit = await db.prepare('SELECT id,items FROM returns').all();
  for (const returnRow of (returnRowsForSaleEdit.results || [])) {
    let returnItems=[];
    try { returnItems = typeof returnRow.items === 'string' ? JSON.parse(returnRow.items || '[]') : (returnRow.items || []); } catch { returnItems=[]; }
    if (Array.isArray(returnItems) && returnItems.some(item => String(item?.sourceSaleId || '') === saleId)) {
      return json({success:false,error:'ئەم فاکتۆرە مرجوعاتی بەستراوی هەیە؛ پێش دەستکاری فاکتۆرەکە سەرەتا مرجوعاتەکە چارەسەر بکە.'},409);
    }
  }
  const oldProductIds = new Set(oldItems.filter(x => x && !x.manual && x.product).map(x => String(x.product)));
  const submittedProductIds = [...new Set(s.items.filter(x => x && !x.manual && x.product).map(x => String(x.product)))];
  const existingProductIds = new Set();
  for (const pid of submittedProductIds) {
    const product = await db.prepare('SELECT id FROM products WHERE id=?').bind(pid).first();
    if (product) existingProductIds.add(pid);
    else if (!oldProductIds.has(pid)) {
      return json({success:false,error:`کاڵا (${pid}) لە کۆگا نییە؛ تکایە لە کۆگا زیاد بکە یان وەک کاڵای دەستی هەڵیبژێرە.`},409);
    }
  }

  let items = s.items.map(x => {
    const submittedProduct = x.manual ? null : (x.product || null);
    // If this line belonged to the original sale but its product was deleted,
    // preserve it as a manual historical line. It no longer changes inventory.
    const missingHistoricalProduct = !!submittedProduct && !existingProductIds.has(String(submittedProduct)) && oldProductIds.has(String(submittedProduct));
    return {
      ...x,
      product: missingHistoricalProduct ? null : submittedProduct,
      manual: !!x.manual || missingHistoricalProduct,
      name: String(x.name || '').trim().slice(0,200),
      qty: Number(x.qty), price: Number(x.price)
    };
  });
  if (items.some(x => !x.name || !(x.qty > 0) || !Number.isFinite(x.qty) || !Number.isFinite(x.price) || x.price < 0)) {
    return json({success:false,error:'ژمارە یان نرخی کاڵا دروست نییە.'},400);
  }
  // Preserve historical cost snapshots for products already on this invoice.
  // A newly introduced product must use its current buy price, rather than inheriting
  // a stale cost snapshot left behind when a user changed a row's selected product.
  const historicalCostByProduct = new Map();
  for (const oldItem of oldItems) {
    if (!oldItem?.manual && oldItem?.product && oldItem.costPrice !== undefined && oldItem.costPrice !== null && Number.isFinite(Number(oldItem.costPrice))) {
      const pid = String(oldItem.product);
      if (!historicalCostByProduct.has(pid)) historicalCostByProduct.set(pid, Math.max(0, Number(oldItem.costPrice)));
    }
  }
  const costByProduct = new Map();
  for (const item of items) {
    if (!item.manual && item.product && !costByProduct.has(String(item.product))) {
      const p = await db.prepare('SELECT buy FROM products WHERE id=?').bind(String(item.product)).first();
      if (p) costByProduct.set(String(item.product), Math.max(0, Number(p.buy || 0)));
    }
  }
  items = items.map(item => {
    const pid = String(item.product || '');
    const oldCost = oldProductIds.has(pid) ? historicalCostByProduct.get(pid) : undefined;
    const selectedCost = oldCost !== undefined ? oldCost : (costByProduct.get(pid) ?? 0);
    return {...item, costPrice: Math.max(0, Number(selectedCost) || 0)};
  });
  const subtotal = items.reduce((sum,x)=>sum+x.qty*x.price,0);
  const discount = Math.min(Math.max(Number(s.discount ?? oldSale.discount ?? 0) || 0,0),subtotal);
  const total = Math.max(0,subtotal-discount);
  const customer = String(s.customer || '').trim().slice(0,120);
  const customerPhone = String(s.customerPhone || '').trim().slice(0,80);
  const requestedType = s.paymentType === 'cash' ? 'cash' : 'credit';
  const paidAmount = requestedType === 'cash' ? total : Math.min(total,Math.max(0,Number(s.paidAmount ?? 0) || 0));
  const debtAmount = Math.max(0,total-paidAmount);
  const paymentType = debtAmount > 0 ? (paidAmount > 0 ? 'partial' : 'credit') : 'cash';
  if (debtAmount > 0 && !customer) return json({success:false,error:'بۆ فاکتۆری قەرز ناوی کڕیار پێویستە.'},400);

  const oldQty = new Map(), newQty = new Map(), newPrices = new Map();
  for (const x of oldItems) if (x && !x.manual && x.product) oldQty.set(String(x.product),(oldQty.get(String(x.product))||0)+Math.max(0,Number(x.qty)||0));
  for (const x of items) if (!x.manual && x.product) {
    const pid=String(x.product); newQty.set(pid,(newQty.get(pid)||0)+x.qty); newPrices.set(pid,x.price);
  }

  const linkedResult = await db.prepare('SELECT * FROM debts WHERE note LIKE ?').bind(`%[فاکتۆر:${saleId}]%`).all();
  const linkedDebts = linkedResult.results || [];
  const invoicePayments = await db.prepare('SELECT debtId,COALESCE(SUM(amount),0) AS paid FROM payments WHERE note LIKE ? GROUP BY debtId').bind(`%[فاکتۆر:${saleId}]%`).all();
  const historicalPaid = (invoicePayments.results || []).reduce((sum,p)=>sum+Math.max(0,Number(p.paid||0)),0);
  if(historicalPaid > debtAmount + 1e-8) return json({success:false,error:'قەرزی نوێ لە پارەی پێشتر وەرگیراو کەمترە؛ بۆ پاراستنی حساب، سەرەتا پارەدان/گەڕاندنەوەکە چارەسەر بکە.'},409);
  const openDebtAmount = Math.max(0, debtAmount - historicalPaid);

  const productIds = new Set([...oldQty.keys(),...newQty.keys()]);
  const statements=[];
  for (const pid of productIds) {
    const p=await db.prepare('SELECT id,name,qty,sell FROM products WHERE id=?').bind(pid).first();
    const requestedNew=Number(newQty.get(pid)||0);
    if (!p && requestedNew > 0) return json({success:false,error:`کاڵا (${pid}) لە کۆگا نییە؛ فاکتۆرەکە نوێ ناکرێتەوە.`},409);
    if (!p) continue;
    const before=Number(p.qty||0), restore=Number(oldQty.get(pid)||0), take=requestedNew;
    const after=before+restore-take;
    if (after < -1e-8) return json({success:false,error:`کۆگای ${p.name} بەشی پێویست نییە.`},409);
    const changedPrice=newPrices.has(pid);
    statements.push(changedPrice
      ? db.prepare('UPDATE products SET qty=?,sell=? WHERE id=? AND qty=?').bind(Math.max(0,after),newPrices.get(pid),pid,before)
      : db.prepare('UPDATE products SET qty=? WHERE id=? AND qty=?').bind(Math.max(0,after),pid,before));
    altinAppendChangeGuard(statements, db);
    if (Math.abs(after-before)>1e-8) statements.push(db.prepare(`INSERT INTO stock_movements(id,date,productId,type,qty,beforeQty,afterQty,refId,note) VALUES(?,?,?,?,?,?,?,?,?)`).bind(
      crypto.randomUUID(),new Date().toISOString(),pid,'sale-edit',after-before,before,Math.max(0,after),saleId,'دەستکاری فاکتۆر'
    ));
  }

  const customerDebts = await db.prepare('SELECT id,name,amount,note FROM debts').all();
  const linkedIds=new Set(linkedDebts.map(d=>String(d.id)));
  const previousDebt = customer ? (customerDebts.results||[]).filter(d=>!linkedIds.has(String(d.id)) && !String(d.id||'').startsWith('purchase-') && !String(d.note||'').includes('قەرزی کڕین') && String(d.name||'').trim().toLowerCase()===customer.toLowerCase()).reduce((sum,d)=>sum+Number(d.amount||0),0) : 0;
  const date = s.date || oldSale.date || new Date().toISOString();
  const canonicalReason=JSON.stringify({subtotal,discount,total,paidAmount,debtAmount});
  statements.push(db.prepare(`UPDATE sales SET date=?,items=?,total=?,customer=?,customerPhone=?,paymentType=?,previousDebt=?,reason=?,subtotal=?,discount=?,paidAmount=?,debtAmount=? WHERE id=?`).bind(
    date,JSON.stringify(items),total,customer,customerPhone,paymentType,previousDebt,canonicalReason,subtotal,discount,paidAmount,debtAmount,saleId
  ));

  const invoiceNote=`قەرزی فاکتۆر - ${customerPhone} [فاکتۆر:${saleId}]`;
  const reusableDebtId = linkedDebts[0]?.id || (invoicePayments.results || []).find(p=>p.debtId)?.debtId || crypto.randomUUID();
  if (openDebtAmount > 1e-8) {
    if (linkedDebts.length) {
      const first=linkedDebts[0];
      statements.push(db.prepare('UPDATE debts SET name=?,amount=?,note=?,date=? WHERE id=? AND amount=?').bind(customer,openDebtAmount,invoiceNote,date,first.id,Number(first.amount||0)));
      altinAppendChangeGuard(statements, db);
      for (const extra of linkedDebts.slice(1)) {
        statements.push(db.prepare('DELETE FROM debts WHERE id=? AND amount=?').bind(extra.id,Number(extra.amount||0)));
        altinAppendChangeGuard(statements, db);
      }
    } else {
      statements.push(db.prepare('INSERT INTO debts(id,name,amount,note,date,currency) VALUES(?,?,?,?,?,?)').bind(reusableDebtId,customer,openDebtAmount,invoiceNote,date,s.currency==='USD'?'USD':'IQD'));
    }
  } else {
    for (const d of linkedDebts) {
      statements.push(db.prepare('DELETE FROM debts WHERE id=? AND amount=?').bind(d.id,Number(d.amount||0)));
      altinAppendChangeGuard(statements, db);
    }
  }
  statements.push(db.prepare('INSERT INTO audit_logs(id,date,action,entity,entityId,details,actor) VALUES(?,?,?,?,?,?,?)').bind(
    crypto.randomUUID(),new Date().toISOString(),'EDIT','sale',saleId,JSON.stringify({subtotal,discount,total,paidAmount,debtAmount,customer,items}),s.actor||'system'
  ));
  const conflict = await altinBatchOrConflict(db, statements, json);
  if (conflict) return conflict;
  return json({success:true,id:saleId,total,subtotal,discount,paidAmount,debtAmount,paymentType,previousDebt});
}

/* =========================================================
   SAFE DELETE FOR INVENTORY-AFFECTING TRANSACTIONS
========================================================= */
async function altinDeleteRecord(table, id, db, actor, json) {
  const allowedTables = new Set(['products','sales','purchases','expenses','debts','returns','payments','audit','stock-movements']);
  if (!allowedTables.has(table)) return json({success:false,error:'Invalid endpoint'},400);
  const realTable = table === 'stock-movements' ? 'stock_movements' : (table === 'audit' ? 'audit_logs' : table);
  const row = await db.prepare(`SELECT * FROM ${realTable} WHERE id=?`).bind(id).first();
  if (!row) return json({success:false,error:'تۆمارەکە نەدۆزرایەوە.'},404);
  if (table === 'debts') {
    const payments = await db.prepare('SELECT COUNT(*) AS n FROM payments WHERE debtId=?').bind(id).first();
    if (Number(payments?.n||0)>0) return json({success:false,error:'ئەم قەرزە مێژووی پارەدان هەیە؛ سڕینەوەی ڕاستەوخۆ ڕێگەپێدراو نییە.'},409);
  }
  const statements=[];
  const now=new Date().toISOString();
  if (table === 'payments') {
    const debtId=String(row.debtId||'');
    const paid=Math.max(0,Number(row.amount||0));
    if(debtId && paid>0) {
      const current=await db.prepare('SELECT id,amount,name,note,date,currency FROM debts WHERE id=?').bind(debtId).first();
      if(current) {
        const currentAmount=Math.max(0,Number(current.amount||0));
        const restored=currentAmount+paid;
        statements.push(db.prepare('UPDATE debts SET amount=? WHERE id=? AND amount=?').bind(restored,debtId,currentAmount));
        altinAppendChangeGuard(statements,db);
      } else {
        let restored=paid;
        let name=String(row.customer||'کڕیار');
        let note=String(row.note||'قەرز گەڕێندرایەوە بەهۆی هەڵوەشاندنەوەی پارەدان').slice(0,500);
        let date=String(row.date||now);
        let currency=row.currency==='USD'?'USD':'IQD';
        if(debtId.startsWith('purchase-')) {
          const purchase=await db.prepare('SELECT supplier,debtAmount,date,currency FROM purchases WHERE id=?').bind(debtId.slice('purchase-'.length)).first();
          if(purchase) {
            const paidElsewhere=await db.prepare('SELECT COALESCE(SUM(amount),0) AS total FROM payments WHERE debtId=? AND id<>?').bind(debtId,id).first();
            restored=Math.max(0,Number(purchase.debtAmount||0)-Number(paidElsewhere?.total||0));
            name=String(purchase.supplier||name); date=String(purchase.date||date); currency=purchase.currency==='USD'?'USD':'IQD';
            note=`قەرزی کڕین • ژمارە: ${debtId.slice('purchase-'.length)}`;
          }
        } else {
          const marker=String(row.note||'').match(/\[فاکتۆر:([^\]]+)\]/);
          if(marker) {
            const saleId=String(marker[1]).trim();
            const sale=await db.prepare('SELECT customer,customerPhone,debtAmount,date FROM sales WHERE id=?').bind(saleId).first();
            if(sale) {
              const paidElsewhere=await db.prepare('SELECT COALESCE(SUM(amount),0) AS total FROM payments WHERE debtId=? AND id<>?').bind(debtId,id).first();
              const returnRows=await db.prepare('SELECT items FROM returns').all();
              let returnedValue=0;
              for(const returnRow of (returnRows.results||[])) {
                let returnItems=[];
                try{returnItems=typeof returnRow.items==='string'?JSON.parse(returnRow.items||'[]'):(returnRow.items||[]);}catch{returnItems=[];}
                if(Array.isArray(returnItems)) for(const item of returnItems) if(String(item?.sourceSaleId||'')===saleId) returnedValue+=Math.max(0,Number(item.qty)||0)*Math.max(0,Number(item.price)||0);
              }
              restored=Math.max(0,Number(sale.debtAmount||0)-Number(paidElsewhere?.total||0)-returnedValue);
              name=String(sale.customer||name); date=String(sale.date||date); currency='IQD';
              note=`قەرزی فاکتۆر - ${String(sale.customerPhone||'')} [فاکتۆر:${saleId}]`;
            }
          }
        }
        if(restored>1e-8) statements.push(db.prepare('INSERT INTO debts(id,name,amount,note,date,currency) VALUES(?,?,?,?,?,?)').bind(debtId,name,restored,note,date,currency));
      }
    }
  }
  if (table === 'sales') {
    const paymentHistory=await db.prepare('SELECT COUNT(*) AS n FROM payments WHERE note LIKE ?').bind(`%[فاکتۆر:${id}]%`).first();
    if(Number(paymentHistory?.n||0)>0) return json({success:false,error:'ئەم فاکتۆرە مێژووی پارەدان هەیە؛ بۆ پاراستنی حساب ناتوانرێت بسڕدرێتەوە.'},409);
    const returnHistory=await db.prepare('SELECT id,items FROM returns').all();
    for(const ret of (returnHistory.results||[])) {
      let returnItems=[]; try{returnItems=typeof ret.items==='string'?JSON.parse(ret.items||'[]'):(ret.items||[]);}catch{returnItems=[];}
      if(Array.isArray(returnItems) && returnItems.some(x=>String(x?.sourceSaleId||'')===String(id))) return json({success:false,error:'ئەم فاکتۆرە مرجوعاتی بەستراوی هەیە؛ سەرەتا مرجوعاتەکان چارەسەر بکە.'},409);
    }
    let items=[]; try { items=typeof row.items==='string'?JSON.parse(row.items||'[]'):(row.items||[]); } catch { items=[]; }
    if (!Array.isArray(items)) items=[];
    const grouped=new Map();
    for(const x of items) if(x&&!x.manual&&x.product) grouped.set(String(x.product),(grouped.get(String(x.product))||0)+Math.max(0,Number(x.qty)||0));
    const debts=await db.prepare('SELECT * FROM debts WHERE note LIKE ?').bind(`%[فاکتۆر:${id}]%`).all();
    for(const d of debts.results||[]) {
      const p=await db.prepare('SELECT COUNT(*) AS n FROM payments WHERE debtId=?').bind(d.id).first();
      if(Number(p?.n||0)>0) return json({success:false,error:'ئەم فاکتۆرە پارەدانی پێشتر هەیە؛ بۆ پاراستنی مێژوو ناتوانرێت بسڕدرێتەوە.'},409);
      statements.push(db.prepare('DELETE FROM debts WHERE id=?').bind(d.id));
    }
    for(const [pid,qty] of grouped) {
      const p=await db.prepare('SELECT id,name,qty FROM products WHERE id=?').bind(pid).first();
      if(!p) continue;
      const before=Number(p.qty||0), after=before+qty;
      statements.push(db.prepare('UPDATE products SET qty=? WHERE id=? AND qty=?').bind(after,pid,before));
      altinAppendChangeGuard(statements, db);
      statements.push(db.prepare('INSERT INTO stock_movements(id,date,productId,type,qty,beforeQty,afterQty,refId,note) VALUES(?,?,?,?,?,?,?,?,?)').bind(crypto.randomUUID(),now,pid,'sale-delete',qty,before,after,id,'گەڕاندنەوەی کۆگا لە سڕینەوەی فاکتۆر'));
    }
  } else if (table === 'purchases') {
    const p=await db.prepare('SELECT id,name,qty,buy FROM products WHERE id=?').bind(row.product).first();
    const qty=Math.max(0,Number(row.qty)||0);
    if(p && Number(p.qty||0)+1e-8<qty) return json({success:false,error:`ناتوانرێت ئەم کڕینە بسڕدرێتەوە؛ ژمارەی ئێستای (${p.name}) کەمترە لە ژمارەی ئەم کڕینە.`},409);
    const debtId=`purchase-${id}`;
    const pay=await db.prepare('SELECT COUNT(*) AS n FROM payments WHERE debtId=?').bind(debtId).first();
    if(Number(pay?.n||0)>0) return json({success:false,error:'ئەم قەرزی کڕینە پارەدانی تۆمارکراوی هەیە؛ سەرەتا پارەدانەکان چارەسەر بکە.'},409);
    statements.push(db.prepare('DELETE FROM debts WHERE id=?').bind(debtId));
    if(p) {
      const previous=await db.prepare('SELECT price,currency,buyIQD FROM purchases WHERE product=? AND id<>? ORDER BY date DESC LIMIT 1').bind(row.product,id).first();
      const nextQty=Math.max(0,Number(p.qty||0)-qty);
      const previousBuy=previous ? (Number(previous.buyIQD)>0 ? Number(previous.buyIQD) : (String(previous.currency||'IQD').toUpperCase()==='USD' ? Number(previous.price||0)*1310 : Number(previous.price||0))) : 0;
      statements.push(previous
        ? db.prepare('UPDATE products SET qty=?,buy=? WHERE id=? AND qty=?').bind(nextQty,previousBuy,p.id,Number(p.qty||0))
        : db.prepare('UPDATE products SET qty=? WHERE id=? AND qty=?').bind(nextQty,p.id,Number(p.qty||0)));
      altinAppendChangeGuard(statements, db);
      statements.push(db.prepare('INSERT INTO stock_movements(id,date,productId,type,qty,beforeQty,afterQty,refId,note) VALUES(?,?,?,?,?,?,?,?,?)').bind(crypto.randomUUID(),now,p.id,'purchase-delete',-qty,Number(p.qty||0),nextQty,id,'کەمکردنەوەی کۆگا لە سڕینەوەی کڕین'));
    }
  } else if (table === 'returns') {
    let items=[]; try { items=typeof row.items==='string'?JSON.parse(row.items||'[]'):(row.items||[]); } catch { items=[]; }
    if (!Array.isArray(items)) items=[];
    const grouped=new Map();
    const returnedBySale=new Map();
    for(const x of items) {
      if(x&&!x.manual&&x.product) grouped.set(String(x.product),(grouped.get(String(x.product))||0)+Math.max(0,Number(x.qty)||0));
      const saleId=String(x?.sourceSaleId||'');
      if(saleId) returnedBySale.set(saleId,(returnedBySale.get(saleId)||0)+Math.max(0,Number(x.qty)||0)*Math.max(0,Number(x.price)||0));
    }
    for(const [pid,qty] of grouped) {
      const p=await db.prepare('SELECT id,name,qty FROM products WHERE id=?').bind(pid).first();
      if(!p) continue;
      const before=Number(p.qty||0), after=before-qty;
      if(after < -1e-8) return json({success:false,error:`ناتوانرێت ئەم مرجوعاتە بسڕدرێتەوە؛ کۆگای (${p.name}) بەشی پێویست نییە.`},409);
      statements.push(db.prepare('UPDATE products SET qty=? WHERE id=? AND qty=?').bind(Math.max(0,after),pid,before));
      altinAppendChangeGuard(statements, db);
      statements.push(db.prepare('INSERT INTO stock_movements(id,date,productId,type,qty,beforeQty,afterQty,refId,note) VALUES(?,?,?,?,?,?,?,?,?)').bind(crypto.randomUUID(),now,pid,'return-delete',-qty,before,Math.max(0,after),id,'گەڕاندنەوەی مرجوعات'));
    }
    const allReturns=await db.prepare('SELECT id,items FROM returns WHERE id<>?').bind(id).all();
    const otherReturnTotals=new Map();
    for(const other of (allReturns.results||[])) {
      let otherItems=[]; try{otherItems=typeof other.items==='string'?JSON.parse(other.items||'[]'):(other.items||[]);}catch{otherItems=[];}
      if(!Array.isArray(otherItems)) continue;
      for(const item of otherItems) {
        const saleId=String(item?.sourceSaleId||'');
        if(saleId) otherReturnTotals.set(saleId,(otherReturnTotals.get(saleId)||0)+Math.max(0,Number(item.qty)||0)*Math.max(0,Number(item.price)||0));
      }
    }
    for (const [saleId] of returnedBySale) {
      const sale=await db.prepare('SELECT id,debtAmount,customer,customerPhone,date FROM sales WHERE id=?').bind(saleId).first();
      if(!sale) continue;
      const linkedDebt=await db.prepare('SELECT id,amount FROM debts WHERE note LIKE ? ORDER BY date LIMIT 1').bind(`%[فاکتۆر:${saleId}]%`).first();
      const taggedPayment=await db.prepare('SELECT debtId FROM payments WHERE note LIKE ? ORDER BY date LIMIT 1').bind(`%[فاکتۆر:${saleId}]%`).first();
      const debtId=String(linkedDebt?.id||taggedPayment?.debtId||crypto.randomUUID());
      const paidRow=await db.prepare('SELECT COALESCE(SUM(amount),0) AS paid FROM payments WHERE debtId=?').bind(debtId).first();
      const target=Math.max(0,Number(sale.debtAmount||0)-Number(paidRow?.paid||0)-Number(otherReturnTotals.get(saleId)||0));
      const current=await db.prepare('SELECT id,amount FROM debts WHERE id=?').bind(debtId).first();
      const currentAmount = Number(current?.amount||0);
      if(target>1e-8) {
        const linkedNote=`قەرزی فاکتۆر - ${String(sale.customerPhone||'')} [فاکتۆر:${saleId}]`;
        statements.push(current
          ? db.prepare('UPDATE debts SET amount=?,name=?,note=? WHERE id=? AND amount=?').bind(target,String(sale.customer||''),linkedNote,debtId,currentAmount)
          : db.prepare('INSERT INTO debts(id,name,amount,note,date,currency) VALUES(?,?,?,?,?,?)').bind(debtId,String(sale.customer||''),target,linkedNote,String(sale.date||now),'IQD'));
        if (current) altinAppendChangeGuard(statements,db);
      } else if(current) {
        statements.push(db.prepare('DELETE FROM debts WHERE id=? AND amount=?').bind(debtId,currentAmount));
        altinAppendChangeGuard(statements,db);
      }
    }
  }
  statements.push(db.prepare(`DELETE FROM ${realTable} WHERE id=?`).bind(id));
  altinAppendChangeGuard(statements, db);
  statements.push(db.prepare('INSERT INTO audit_logs(id,date,action,entity,entityId,details,actor) VALUES(?,?,?,?,?,?,?)').bind(crypto.randomUUID(),now,'DELETE',table,id,JSON.stringify({recordDate:row.date||'',name:row.name||row.customer||''}),actor||'system'));
  const conflict = await altinBatchOrConflict(db, statements, json);
  if (conflict) return conflict;
  return json({success:true,id});
}

/* =========================================================
   RETURN TRANSACTION
========================================================= */

async function returnTransaction(x, db, json) {
  if (!x?.id || !Array.isArray(x.items) || !x.items.length) {
    return json({ error: "Invalid return" }, 400);
  }
  const items = x.items.map(item => ({
    ...item, qty: Number(item.qty), price: Number(item.price)
  }));
  if (items.some(item => !(item.qty > 0) || !Number.isFinite(item.qty) || !Number.isFinite(item.price) || item.price < 0)) {
    return json({ error: "Invalid return item quantity or price" }, 400);
  }

  const grouped = new Map();
  for (const item of items) {
    if (item.product && !item.manual) grouped.set(item.product, (grouped.get(item.product) || 0) + item.qty);
  }
  const products = [];
  for (const productId of grouped.keys()) {
    const product = await db.prepare("SELECT * FROM products WHERE id=?").bind(productId).first();
    if (!product) return json({ error: `Product ${productId} not found` }, 400);
    products.push(product);
  }
  const productById = new Map(products.map(p => [String(p.id), p]));
  const sourceSaleIds = [...new Set(items.map(item => String(item.sourceSaleId || x.sourceSaleId || "")).filter(Boolean))];
  const sourceSales = new Map();
  for (const sourceSaleId of sourceSaleIds) {
    const row = await db.prepare("SELECT id,date,items,debtAmount,customer,customerPhone,paymentType FROM sales WHERE id=?").bind(sourceSaleId).first();
    if (!row) return json({error:"فاتورەی فرۆشتنی بنەڕەت نەدۆزرایەوە."},400);
    let sourceItems;
    try { sourceItems = typeof row.items === "string" ? JSON.parse(row.items || "[]") : row.items; } catch { sourceItems = []; }
    sourceSales.set(sourceSaleId, { ...row, items: Array.isArray(sourceItems) ? sourceItems : [] });
  }
  // If a return is linked to an original sale, reject quantities exceeding
  // the quantity sold after counting earlier returns that were also linked to
  // the same sale. Unlinked historical returns cannot be attributed safely.
  if (sourceSaleIds.length) {
    const existingReturns = await db.prepare("SELECT items FROM returns").all();
    const returnedQty = new Map();
    for (const row of (existingReturns.results || [])) {
      let priorItems;
      try { priorItems = typeof row.items === "string" ? JSON.parse(row.items || "[]") : row.items; } catch { priorItems = []; }
      if (!Array.isArray(priorItems)) continue;
      for (const prior of priorItems) {
        const saleId = String(prior?.sourceSaleId || "");
        const productId = String(prior?.product || "");
        if (!saleId || !productId || !sourceSales.has(saleId)) continue;
        const key = `${saleId}\u0000${productId}`;
        returnedQty.set(key, (returnedQty.get(key) || 0) + Math.max(0, Number(prior.qty) || 0));
      }
    }
    const requestedQty = new Map();
    for (const item of items) {
      const saleId = String(item.sourceSaleId || x.sourceSaleId || "");
      const productId = String(item.product || "");
      if (!saleId || !productId) continue;
      const key = `${saleId}\u0000${productId}`;
      requestedQty.set(key, (requestedQty.get(key) || 0) + Math.max(0, Number(item.qty) || 0));
    }
    for (const [key, qty] of requestedQty) {
      const [saleId, productId] = key.split("\u0000");
      const sale = sourceSales.get(saleId);
      const saleQty = (sale?.items || []).filter(line => !line.manual && String(line.product || "") === productId)
        .reduce((sum, line) => sum + Math.max(0, Number(line.qty) || 0), 0);
      const alreadyReturned = returnedQty.get(key) || 0;
      if (saleQty <= 0 || alreadyReturned + qty > saleQty + 1e-8) {
        return json({success:false,error:"ژمارەی مرجوعات ناتوانێت لە ژمارەی کاڵای فرۆشراو زیاتر بێت. فاتورە و بڕی گەڕاندنەوە بپشکنە."},409);
      }
    }
  }

  const savedItems = [];
  for (const item of items) {
    const p = item.product && !item.manual ? productById.get(String(item.product)) : null;
    const sourceSaleId = String(item.sourceSaleId || x.sourceSaleId || "");
    const sourceSale = sourceSaleId ? sourceSales.get(sourceSaleId) : null;
    const sourceItem = sourceSale
      ? sourceSale.items.find(s => !s.manual && String(s.product || "") === String(item.product || ""))
      : null;
    if (sourceSale && (!item.product || !sourceItem)) {
      return json({error:"کاڵای مرجوعکراو لە فاتورەی فرۆشتنی هەڵبژێردراودا نییە."},400);
    }
    // When an original sale is linked, use its stored historical unit cost.
    // Without a linked sale, freeze the current stock cost at the moment of return.
    const rawCost = sourceSale
      ? (sourceItem.costPrice !== undefined && sourceItem.costPrice !== null && Number.isFinite(Number(sourceItem.costPrice))
          ? Number(sourceItem.costPrice)
          : Math.max(0, Number(p?.buy || 0)))
      : (p ? Math.max(0, Number(p.buy || 0)) : Math.max(0, Number(item.costPrice || 0)));
    savedItems.push({
      ...item,
      ...(sourceSale ? {sourceSaleId} : {}),
      costPrice: Math.max(0, rawCost)
    });
  }

  const total = savedItems.reduce((sum, item) => sum + item.qty * item.price, 0);
  const date = x.date || new Date().toISOString();
  const returnId = String(x.id);
  const statements = [];
  for (const product of products) {
    const qty = grouped.get(product.id);
    statements.push(db.prepare("UPDATE products SET qty=qty+? WHERE id=? AND qty=?").bind(qty, product.id, Number(product.qty||0)));
    altinAppendChangeGuard(statements, db);
    statements.push(db.prepare(`INSERT INTO stock_movements
      (id,date,productId,type,qty,beforeQty,afterQty,refId,note) VALUES (?,?,?,?,?,?,?,?,?)`).bind(
        crypto.randomUUID(), date, product.id, "return", qty, Number(product.qty || 0),
        Number(product.qty || 0) + qty, returnId, "گەڕاندنەوەی کاڵا"
      ));
  }
  // Offset any still-open invoice debt for returns linked to a source invoice.
  // If the refund exceeds the open debt, retain the excess in the audit record.
  const returnTotalsBySale = new Map();
  for (const item of savedItems) {
    const saleId = String(item.sourceSaleId || x.sourceSaleId || "");
    if (saleId) returnTotalsBySale.set(saleId, (returnTotalsBySale.get(saleId) || 0) + Number(item.qty) * Number(item.price));
  }
  let totalDebtOffset = 0;
  let totalRefundDue = 0;
  for (const [saleId, requestedOffset] of returnTotalsBySale) {
    const linked = await db.prepare("SELECT id,amount FROM debts WHERE note LIKE ? ORDER BY date ASC")
      .bind(`%[فاکتۆر:${saleId}]%`).all();
    let remainingOffset = Math.max(0, requestedOffset);
    for (const debt of (linked.results || [])) {
      if (remainingOffset <= 0) break;
      const current = Math.max(0, Number(debt.amount || 0));
      const applied = Math.min(current, remainingOffset);
      if (applied <= 0) continue;
      const next = current - applied;
      statements.push(next <= 1e-8
        ? db.prepare("DELETE FROM debts WHERE id=? AND amount=?").bind(debt.id,current)
        : db.prepare("UPDATE debts SET amount=? WHERE id=? AND amount=?").bind(next,debt.id,current));
      altinAppendChangeGuard(statements, db);
      remainingOffset -= applied;
      totalDebtOffset += applied;
    }
    totalRefundDue += remainingOffset;
  }
  statements.push(db.prepare(`INSERT INTO returns (id,date,items,total,customer,reason) VALUES (?,?,?,?,?,?)`).bind(
    returnId, date, JSON.stringify(savedItems), total, String(x.customer || "سەردانکەر"), String(x.reason || "نادیار")
  ));
  statements.push(db.prepare(`INSERT INTO audit_logs (id,date,action,entity,entityId,details,actor) VALUES (?,?,?,?,?,?,?)`).bind(
    crypto.randomUUID(), date, "RETURN", "return", returnId,
    JSON.stringify({ total, debtOffset:totalDebtOffset, refundDue:totalRefundDue, customer: x.customer || "", items: savedItems }), x.actor || "system"
  ));
  const conflict = await altinBatchOrConflict(db, statements, json);
  if (conflict) return conflict;
  return json({ success: true, id: returnId, total, debtOffset: totalDebtOffset, refundDue: totalRefundDue });
}

/* =========================================================
   PURCHASE BASKET — all lines commit atomically as one supplier invoice
========================================================= */
async function purchaseBatchTransaction(x, db, json) {
  const rawItems = Array.isArray(x?.items) ? x.items : [];
  if (!rawItems.length) return json({success:false,error:"سەبەتەی کڕین بەتاڵە."},400);
  if (rawItems.length > 100) return json({success:false,error:"لە هەر فاتورەیەکدا زیاتر لە ١٠٠ ڕیزی کاڵا ناتوانرێت تۆمار بکرێت."},400);

  const items=[];
  const seenIds=new Set();
  for (const raw of rawItems) {
    const productId=String(raw?.product||'').trim();
    const qty=Number(raw?.qty), price=Number(raw?.price);
    if (!productId || !(qty>0) || !Number.isFinite(qty) || !Number.isFinite(price) || price<0) {
      return json({success:false,error:"کاڵا، ژمارە یان نرخی یەکێک لە ڕیزەکانی سەبەتە دروست نییە."},400);
    }
    const p=await db.prepare("SELECT * FROM products WHERE id=?").bind(productId).first();
    if (!p) return json({success:false,error:"یەکێک لە کاڵاکانی سەبەتە لە کۆگادا نەدۆزرایەوە؛ تکایە داتاکان نوێ بکەرەوە."},409);
    const purchaseId=String(raw.id||crypto.randomUUID());
    if (seenIds.has(purchaseId)) return json({success:false,error:"ژمارەی فاتورەی دووبارە هەیە."},400);
    seenIds.add(purchaseId);
    const lineTotal=qty*price;
    if (!Number.isFinite(lineTotal)) return json({success:false,error:"کۆی نرخی یەکێک لە کاڵاکان زۆر گەورەیە."},400);
    items.push({id:purchaseId,product:productId,qty,price,lineTotal,p});
  }

  const total=items.reduce((sum,item)=>sum+item.lineTotal,0);
  if (!Number.isFinite(total)) return json({success:false,error:"کۆی گشتیی کڕین دروست نییە."},400);
  const paymentType=x.paymentType==="credit"?"credit":"cash";
  const currency=String(x.currency||"IQD").toUpperCase()==="USD"?"USD":"IQD";
  const supplier=String(x.supplier||"").trim();
  if (paymentType==="credit" && !supplier) return json({success:false,error:"بۆ کڕینی قەرز، ناوی فرۆشیار/کۆمپانیا پێویستە."},400);
  const date=String(x.date||new Date().toISOString());
  const batchId=String(x.batchId||crypto.randomUUID());
  let paidAmount=paymentType==="cash"?total:Math.max(0,Number(x.paidAmount)||0);
  if (!Number.isFinite(paidAmount)) return json({success:false,error:"بڕی پارەی دراو دروست نییە."},400);
  paidAmount=Math.min(total,paidAmount);
  const savedFxRaw=Number(await megaGet(db,"usdRate",1310));
  const exchangeRate=Number.isFinite(savedFxRaw)&&savedFxRaw>=1&&savedFxRaw<=1000000000?savedFxRaw:1310;
  for (const item of items) {
    item.buyIQD=currency==="USD"?item.price*exchangeRate:item.price;
    if (!Number.isFinite(item.buyIQD)) return json({success:false,error:"نرخی کڕین بە دینار هەژمار نەکرایەوە."},400);
  }

  // Allocate the invoice payment proportionally across lines; the final line absorbs rounding drift.
  let paidAssigned=0;
  for (let i=0;i<items.length;i++) {
    const item=items[i];
    item.paidAmount = i===items.length-1
      ? Math.max(0,Math.min(item.lineTotal,paidAmount-paidAssigned))
      : (total>0?Math.min(item.lineTotal,paidAmount*item.lineTotal/total):0);
    paidAssigned+=item.paidAmount;
    item.debtAmount=Math.max(0,item.lineTotal-item.paidAmount);
  }

  // Update each product once, while preserving per-line prices and stock movement history.
  const groups=new Map();
  for (const item of items) {
    if(!groups.has(item.product)) groups.set(item.product,{product:item.p,qty:0,finalBuyIQD:item.buyIQD,items:[]});
    const group=groups.get(item.product);group.qty+=item.qty;group.finalBuyIQD=item.buyIQD;group.items.push(item);
  }
  const statements=[];
  for (const [productId,group] of groups) {
    const before=Number(group.product.qty||0),after=before+group.qty;
    statements.push(db.prepare("UPDATE products SET qty=qty+?,buy=? WHERE id=? AND qty=?")
      .bind(group.qty,group.finalBuyIQD,productId,before));
    altinAppendChangeGuard(statements,db);
    let running=before;
    for (const item of group.items) {
      const next=running+item.qty;
      statements.push(db.prepare("INSERT INTO stock_movements (id,date,productId,type,qty,beforeQty,afterQty,refId,note) VALUES (?,?,?,?,?,?,?,?,?)")
        .bind(crypto.randomUUID(),date,productId,"purchase",item.qty,running,next,item.id,"کڕین • سەبەتەی کڕین"));
      running=next;
    }
  }

  for (const item of items) {
    statements.push(db.prepare("INSERT INTO purchases (id,product,qty,price,supplier,date,paymentType,paidAmount,debtAmount,total,currency,buyIQD,batchId) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
      .bind(item.id,item.product,item.qty,item.price,supplier,date,paymentType,item.paidAmount,item.debtAmount,item.lineTotal,currency,item.buyIQD,batchId));
    if (item.debtAmount>0) {
      statements.push(db.prepare("INSERT INTO debts (id,name,amount,note,date,currency) VALUES (?,?,?,?,?,?)")
        .bind(`purchase-${item.id}`,supplier||"فرۆشیاری نەناسراو",item.debtAmount,`قەرزی کڕین • ژمارە: ${item.id}`,date,currency));
    }
    statements.push(db.prepare("INSERT INTO audit_logs (id,date,action,entity,entityId,details,actor) VALUES (?,?,?,?,?,?,?)")
      .bind(crypto.randomUUID(),date,"CREATE","purchase",item.id,JSON.stringify({batchId,product:item.product,qty:item.qty,price:item.price,buyIQD:item.buyIQD,exchangeRate,total:item.lineTotal,paidAmount:item.paidAmount,debtAmount:item.debtAmount,supplier,paymentType,currency}),x.actor||"system"));
  }
  statements.push(db.prepare("INSERT INTO audit_logs (id,date,action,entity,entityId,details,actor) VALUES (?,?,?,?,?,?,?)")
    .bind(crypto.randomUUID(),date,"CREATE","purchase-batch",batchId,JSON.stringify({count:items.length,total,paidAmount,debtAmount:Math.max(0,total-paidAmount),supplier,paymentType,currency,items:items.map(i=>({id:i.id,product:i.product,qty:i.qty,price:i.price}))}),x.actor||"system"));

  const conflict=await altinBatchOrConflict(db,statements,json);
  if(conflict)return conflict;
  return json({success:true,batchId,ids:items.map(i=>i.id),count:items.length,total,paidAmount,debtAmount:Math.max(0,total-paidAmount),exchangeRate,priceSync:true});
}

/* =========================================================
   PURCHASE
========================================================= */

async function purchaseTransaction(x, db, json) {
  const p = await db.prepare("SELECT * FROM products WHERE id=?").bind(x.product).first();
  if (!p) return json({ error: "Product not found" }, 400);
  const q = Number(x.qty), price = Number(x.price);
  if (!(q > 0) || !Number.isFinite(q) || !Number.isFinite(price) || price < 0) return json({ error: "Invalid quantity or price" }, 400);

  // Do not trust a client-supplied total: quantity × unit price is canonical.
  const total = q * price;
  if (!Number.isFinite(total)) return json({ error: "Invalid purchase total" }, 400);
  const paymentType = x.paymentType === "credit" ? "credit" : "cash";
  const currency = x.currency === "USD" ? "USD" : "IQD";
  const savedFxRaw = Number(await megaGet(db, "usdRate", 1310));
  const exchangeRate = Number.isFinite(savedFxRaw) && savedFxRaw >= 1 && savedFxRaw <= 1000000000 ? savedFxRaw : 1310;
  const buyIQD = currency === "USD" ? price * exchangeRate : price;
  if (!Number.isFinite(buyIQD)) return json({error:"Invalid IQD-normalized purchase price"},400);
  const paidAmount = paymentType === "cash"
    ? total
    : Math.min(total, Math.max(0, Number(x.paidAmount) || 0));
  const debtAmount = Math.max(0, total - paidAmount);
  const date = x.date || new Date().toISOString();
  const supplier = String(x.supplier || "").trim();
  const purchaseId = x.id || crypto.randomUUID();
  const statements = [
    db.prepare(`UPDATE products SET qty=qty+?, buy=? WHERE id=? AND qty=?`).bind(q, buyIQD, p.id, Number(p.qty||0))
  ];
  altinAppendChangeGuard(statements, db);
  statements.push(
    db.prepare(`INSERT INTO purchases (id,product,qty,price,supplier,date,paymentType,paidAmount,debtAmount,total,currency,buyIQD) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(purchaseId, x.product, q, price, supplier, date, paymentType, paidAmount, debtAmount, total, currency, buyIQD),
    db.prepare(`INSERT INTO stock_movements (id,date,productId,type,qty,beforeQty,afterQty,refId,note) VALUES (?,?,?,?,?,?,?,?,?)`)
      .bind(crypto.randomUUID(), date, p.id, "purchase", q, p.qty, Number(p.qty) + q, purchaseId, "کڕین"),
    db.prepare(`INSERT INTO audit_logs (id,date,action,entity,entityId,details,actor) VALUES (?,?,?,?,?,?,?)`)
      .bind(crypto.randomUUID(), date, "CREATE", "purchase", purchaseId, JSON.stringify({product:p.id,qty:q,price,buyIQD,exchangeRate,total,paidAmount,debtAmount,supplier,paymentType,currency}), x.actor || "system")
  );
  // Supplier debt is recorded in the existing debt ledger, so it appears in the debt center/dashboard
  // and can be settled through the existing payment workflow.
  if (debtAmount > 0) {
    statements.push(db.prepare(`INSERT INTO debts (id,name,amount,note,date,currency) VALUES (?,?,?,?,?,?)`)
      .bind(`purchase-${purchaseId}`, supplier || "فرۆشیاری نەناسراو", debtAmount, `قەرزی کڕین • ژمارە: ${purchaseId}`, date, currency));
  }
  const conflict = await altinBatchOrConflict(db, statements, json);
  if (conflict) return conflict;
  return json({ success: true, id: purchaseId, total, paidAmount, debtAmount, buyIQD, exchangeRate, priceSync: true });
}

/* =========================================================
   SAFE PURCHASE EDIT
   Reconciles the inventory, purchase row and supplier debt atomically.
   Purchases with recorded settlement payments are blocked to preserve the ledger.
========================================================= */
async function editPurchaseTransaction(x, db, json) {
  const id=String(x?.id||'').trim();
  if(!id) return json({success:false,error:'ژمارەی کڕین پێویستە.'},400);
  const old=await db.prepare('SELECT * FROM purchases WHERE id=?').bind(id).first();
  if(!old) return json({success:false,error:'تۆماری کڕین نەدۆزرایەوە.'},404);
  const paymentCount=await db.prepare('SELECT COUNT(*) AS n FROM payments WHERE debtId=?').bind(`purchase-${id}`).first();
  if(Number(paymentCount?.n||0)>0) return json({success:false,error:'ئەم کڕینە مێژووی پارەدان هەیە؛ بۆ پاراستنی مێژوو دەستکاریی کۆیی ڕێگەپێدراو نییە.'},409);
  const oldProductId=String(old.product||'');
  const productId=String(x.product||oldProductId);
  const qty=x.qty===undefined?Number(old.qty):Number(x.qty);
  const price=x.price===undefined?Number(old.price):Number(x.price);
  if(!(qty>0)||!Number.isFinite(qty)||!Number.isFinite(price)||price<0||qty>1e9||price>1e12) return json({success:false,error:'ژمارە یان نرخی کڕین دروست نییە.'},400);
  const product=await db.prepare('SELECT * FROM products WHERE id=?').bind(productId).first();
  if(!product) return json({success:false,error:'کاڵای کڕینەکە نەدۆزرایەوە.'},404);
  const currency=x.currency==='USD'?'USD':x.currency==='IQD'?'IQD':(String(old.currency||'IQD').toUpperCase()==='USD'?'USD':'IQD');
  const savedFxRaw=Number(await megaGet(db,'usdRate',1310));
  const fx=Number.isFinite(savedFxRaw)&&savedFxRaw>=1&&savedFxRaw<=1e9?savedFxRaw:1310;
  const buyIQD=currency==='USD'?price*fx:price;
  const total=qty*price;
  if(!Number.isFinite(total)||!Number.isFinite(buyIQD)) return json({success:false,error:'کۆی نرخی کڕین دروست نییە.'},400);
  const paymentType=x.paymentType===undefined?(String(old.paymentType||'cash')==='credit'?'credit':'cash'):(x.paymentType==='credit'?'credit':'cash');
  const requestedPaid=x.paidAmount===undefined?Number(old.paidAmount||0):Number(x.paidAmount);
  if(!Number.isFinite(requestedPaid)||requestedPaid<0) return json({success:false,error:'بڕی پارەی دراو دروست نییە.'},400);
  const paidAmount=paymentType==='cash'?total:Math.min(total,requestedPaid);
  const debtAmount=Math.max(0,total-paidAmount);
  const supplier=String(x.supplier===undefined?(old.supplier||''):(x.supplier||'')).trim().slice(0,200);
  const date=String(x.date||old.date||new Date().toISOString()).slice(0,50);
  const previousProduct=oldProductId===productId?product:await db.prepare('SELECT * FROM products WHERE id=?').bind(oldProductId).first();
  if(oldProductId!==productId&&!previousProduct) return json({success:false,error:'کاڵای پێشووی ئەم کڕینە لە کۆگا نییە؛ بۆ پاراستنی ژمارەی کۆگا ناتوانرێت بگۆڕدرێت.'},409);
  const statements=[];
  const now=new Date().toISOString();
  if(oldProductId===productId) {
    const before=Number(product.qty||0), delta=qty-Number(old.qty||0), after=before+delta;
    if(after < -1e-8) return json({success:false,error:`کۆگای ${product.name} بەشی پێویست نییە بۆ کەمکردنەوەی ئەم کڕینە.`},409);
    const latest=await db.prepare('SELECT id,date FROM purchases WHERE product=? AND id<>? ORDER BY date DESC,rowid DESC LIMIT 1').bind(productId,id).first();
    const updateBuy= !latest || date >= String(latest.date||'');
    statements.push(updateBuy
      ? db.prepare('UPDATE products SET qty=?,buy=? WHERE id=? AND qty=?').bind(Math.max(0,after),buyIQD,productId,before)
      : db.prepare('UPDATE products SET qty=? WHERE id=? AND qty=?').bind(Math.max(0,after),productId,before));
    altinAppendChangeGuard(statements,db);
    if(Math.abs(delta)>1e-8) statements.push(db.prepare('INSERT INTO stock_movements(id,date,productId,type,qty,beforeQty,afterQty,refId,note) VALUES(?,?,?,?,?,?,?,?,?)').bind(crypto.randomUUID(),now,productId,'purchase-edit',delta,before,Math.max(0,after),id,'دەستکاری کڕین'));
  } else {
    const beforeOld=Number(previousProduct.qty||0), afterOld=beforeOld-Number(old.qty||0);
    if(afterOld < -1e-8) return json({success:false,error:`کۆگای ${previousProduct.name} بۆ گەڕاندنەوەی بڕی کڕینی پێشووی بەشی پێویست نییە.`},409);
    const beforeNew=Number(product.qty||0), afterNew=beforeNew+qty;
    const latestNew=await db.prepare('SELECT id,date FROM purchases WHERE product=? AND id<>? ORDER BY date DESC,rowid DESC LIMIT 1').bind(productId,id).first();
    const updateNewBuy=!latestNew || date>=String(latestNew.date||'');
    statements.push(db.prepare('UPDATE products SET qty=? WHERE id=? AND qty=?').bind(Math.max(0,afterOld),oldProductId,beforeOld));
    altinAppendChangeGuard(statements,db);
    statements.push(updateNewBuy
      ? db.prepare('UPDATE products SET qty=?,buy=? WHERE id=? AND qty=?').bind(afterNew,buyIQD,productId,beforeNew)
      : db.prepare('UPDATE products SET qty=? WHERE id=? AND qty=?').bind(afterNew,productId,beforeNew));
    altinAppendChangeGuard(statements,db);
    statements.push(db.prepare('INSERT INTO stock_movements(id,date,productId,type,qty,beforeQty,afterQty,refId,note) VALUES(?,?,?,?,?,?,?,?,?)').bind(crypto.randomUUID(),now,oldProductId,'purchase-edit',-Number(old.qty||0),beforeOld,Math.max(0,afterOld),id,'گۆڕینی کاڵای کڕین'));
    statements.push(db.prepare('INSERT INTO stock_movements(id,date,productId,type,qty,beforeQty,afterQty,refId,note) VALUES(?,?,?,?,?,?,?,?,?)').bind(crypto.randomUUID(),now,productId,'purchase-edit',qty,beforeNew,afterNew,id,'گۆڕینی کاڵای کڕین'));
  }
  statements.push(db.prepare('UPDATE purchases SET product=?,qty=?,price=?,supplier=?,date=?,paymentType=?,paidAmount=?,debtAmount=?,total=?,currency=?,buyIQD=? WHERE id=?').bind(productId,qty,price,supplier,date,paymentType,paidAmount,debtAmount,total,currency,buyIQD,id));
  const debtId=`purchase-${id}`;
  const currentDebt=await db.prepare('SELECT id,amount FROM debts WHERE id=?').bind(debtId).first();
  if(debtAmount>1e-8) {
    if(currentDebt) {
      statements.push(db.prepare('UPDATE debts SET name=?,amount=?,note=?,date=?,currency=? WHERE id=? AND amount=?').bind(supplier||'فرۆشیاری نەناسراو',debtAmount,`قەرزی کڕین • ژمارە: ${id}`,date,currency,debtId,Number(currentDebt.amount||0)));
      altinAppendChangeGuard(statements,db);
    } else {
      statements.push(db.prepare('INSERT INTO debts(id,name,amount,note,date,currency) VALUES(?,?,?,?,?,?)').bind(debtId,supplier||'فرۆشیاری نەناسراو',debtAmount,`قەرزی کڕین • ژمارە: ${id}`,date,currency));
    }
  } else if(currentDebt) {
    statements.push(db.prepare('DELETE FROM debts WHERE id=? AND amount=?').bind(debtId,Number(currentDebt.amount||0)));
    altinAppendChangeGuard(statements,db);
  }
  statements.push(db.prepare('INSERT INTO audit_logs(id,date,action,entity,entityId,details,actor) VALUES(?,?,?,?,?,?,?)').bind(crypto.randomUUID(),now,'EDIT','purchase',id,JSON.stringify({oldProductId,productId,oldQty:Number(old.qty||0),qty,price,total,paidAmount,debtAmount,currency,supplier}),x.actor||'system'));
  const conflict=await altinBatchOrConflict(db,statements,json);
  if(conflict) return conflict;
  return json({success:true,id,total,paidAmount,debtAmount,currency,buyIQD});
}

/* =========================================================
   PAYMENT
========================================================= */

async function paymentTransaction(
  x,
  db,
  json
) {

  const d =
    await db
      .prepare(
        "SELECT * FROM debts WHERE id=?"
      )
      .bind(x.debtId)
      .first();

  if (!d) {
    return json(
      {
        error:
          "Debt not found"
      },
      404
    );
  }

  const requestedAmount = Number(x.amount);
  const currentDebt = Number(d.amount || 0);
  if (!Number.isFinite(requestedAmount) || !Number.isFinite(currentDebt) || requestedAmount <= 0 || currentDebt <= 0) {
    return json({error:"Invalid payment amount"},400);
  }
  const paid = Math.min(requestedAmount, currentDebt);
  if (!(paid > 0)) {
    return json(
      {
        error:
          "Invalid payment"
      },
      400
    );
  }

  const rem =
    Number(d.amount) -
    paid;

  const isPurchaseDebt = String(d.id || "").startsWith("purchase-") || String(d.note || "").includes("قەرزی کڕین");
  const markers = [...String(d.note || "").matchAll(/\[فاکتۆر:[^\]]+\]/g)].map(m=>m[0]);
  let paymentNote;
  if(isPurchaseDebt) {
    paymentNote = `قەرزی کڕین • ${String(d.note || x.note || "پارەدان").slice(0,400)}`;
  } else {
    paymentNote = String(x.note || d.note || "پارەدان").slice(0,420);
    for(const marker of markers) if(!paymentNote.includes(marker)) paymentNote += ` ${marker}`;
    paymentNote = paymentNote.slice(0,500);
  }

  const statements = [

    db.prepare(
      `INSERT INTO payments
      (
        id,
        debtId,
        customer,
        amount,
        currency,
        note,
        date,
        paymentMethod
      )
      VALUES (?,?,?,?,?,?,?,?)`)
    .bind(
      x.id || crypto.randomUUID(),
      d.id,
      d.name,
      paid,
      d.currency || (x.currency === "USD" ? "USD" : "IQD"),
      paymentNote,
      x.date || new Date().toISOString(),
      String(x.paymentMethod || "نەقد").slice(0,80)
    )

  ];

  if (rem <= 1e-8) {
    statements.push(db.prepare("DELETE FROM debts WHERE id=? AND amount=?").bind(d.id,currentDebt));
    altinAppendChangeGuard(statements,db);
  } else {
    statements.push(db.prepare("UPDATE debts SET amount=? WHERE id=? AND amount=?").bind(rem,d.id,currentDebt));
    altinAppendChangeGuard(statements,db);
  }

  statements.push(
    db.prepare(
      `INSERT INTO audit_logs
      (
        id,
        date,
        action,
        entity,
        entityId,
        details,
        actor
      )
      VALUES (?,?,?,?,?,?,?)`
    ).bind(
      crypto.randomUUID(),
      new Date().toISOString(),
      "PAYMENT",
      "debt",
      d.id,
      JSON.stringify({
        paid,
        remaining:
          Math.max(0, rem),
        customer: d.name
      }),
      x.actor || "system"
    )
  );

  const conflict=await altinBatchOrConflict(db,statements,json);
  if(conflict) return conflict;

  return json({
    success: true,
    paid,
    remaining: Math.max(0, rem),
    currency: d.currency || "IQD"
  });
}


/* =========================================================
   AUDIT INSERT
========================================================= */

async function auditInsert(
  x,
  db,
  json
) {

  await db
    .prepare(
      `INSERT INTO audit_logs
      (
        id,
        date,
        action,
        entity,
        entityId,
        details,
        actor
      )
      VALUES (?,?,?,?,?,?,?)`
    )
    .bind(
      x.id ||
        crypto.randomUUID(),

      x.date ||
        new Date().toISOString(),

      x.action ||
        "CHANGE",

      x.entity || "",

      x.entityId || "",

      x.details || "",

      x.actor ||
        "system"
    )
    .run();

  return json({
    success: true
  });
}

/* =========================================================
   ALTIN MEGA UPGRADE v1
   Server-side settings, users/roles, notifications, 3-day returns
========================================================= */

async function ensureMegaSchema(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS altin_users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      name TEXT DEFAULT '',
      role TEXT DEFAULT 'cashier',
      password TEXT DEFAULT '',
      permissions TEXT DEFAULT '[]',
      active INTEGER DEFAULT 1,
      date TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS altin_settings (
      key TEXT PRIMARY KEY,
      value TEXT DEFAULT '',
      date TEXT NOT NULL
    )`)
  ]);

  // Account creation is handled by altinEnsureAuthSchema and the user-management API.
  // Never seed a known plaintext password or an undocumented privileged account here.
}

async function megaGet(db, key, fallback=null) {
  const r = await db.prepare("SELECT value FROM altin_settings WHERE key=?").bind(key).first();
  if (!r) return fallback;
  try { return JSON.parse(r.value); } catch { return r.value; }
}

async function megaSet(db, key, value) {
  await db.prepare(`INSERT INTO altin_settings(key,value,date)
    VALUES(?,?,?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value,date=excluded.date`)
    .bind(key, JSON.stringify(value), new Date().toISOString()).run();
}

async function altinMigrateCostSnapshots(db) {
  const migrationKey = "accountingCostSnapshotsV1";
  if (await megaGet(db, migrationKey, false) === true) return;

  const [salesResult, purchasesResult, productsResult, returnsResult] = await Promise.all([
    db.prepare("SELECT id,date,items FROM sales").all(),
    db.prepare("SELECT product,date,price,currency,buyIQD FROM purchases ORDER BY date DESC,rowid DESC").all(),
    db.prepare("SELECT id,buy FROM products").all(),
    db.prepare("SELECT id,date,items FROM returns").all()
  ]);
  const sales = salesResult.results || [];
  const purchases = purchasesResult.results || [];
  const products = new Map((productsResult.results || []).map(p => [String(p.id), Math.max(0, Number(p.buy || 0))]));
  const salesById = new Map(sales.map(s => [String(s.id), s]));
  const rate = Math.max(1, Number(await megaGet(db, "usdRate", 1310)) || 1310);

  const dateMs = value => {
    const raw = String(value || "");
    const normalized = /^\d{4}-\d{2}-\d{2}$/.test(raw) ? `${raw}T23:59:59.999Z` : raw;
    const ms = new Date(normalized).getTime();
    return Number.isFinite(ms) ? ms : Number.POSITIVE_INFINITY;
  };
  const historicalCost = (productId, date) => {
    const pid = String(productId || "");
    const boundary = dateMs(date);
    const purchase = purchases.find(p => String(p.product || "") === pid && dateMs(p.date) <= boundary);
    if (purchase) {
      const nativePrice = Math.max(0, Number(purchase.price || 0));
      const normalized = Number(purchase.buyIQD);
      if (Number.isFinite(normalized) && (normalized > 0 || nativePrice === 0)) return normalized;
      return String(purchase.currency || "IQD").toUpperCase() === "USD" ? nativePrice * rate : nativePrice;
    }
    return products.get(pid) || 0;
  };
  const parsedItems = row => {
    try {
      const items = typeof row.items === "string" ? JSON.parse(row.items || "[]") : row.items;
      return Array.isArray(items) ? items : null;
    } catch { return null; }
  };
  const validSnapshot = item => item && item.costPrice !== undefined && item.costPrice !== null && Number.isFinite(Number(item.costPrice));

  const statements = [];
  const migratedSales = new Map();
  for (const sale of sales) {
    const items = parsedItems(sale);
    if (!items) continue;
    let changed = false;
    const next = items.map(item => {
      if (!item || item.manual || !item.product || validSnapshot(item)) return item;
      changed = true;
      return {...item, costPrice: historicalCost(item.product, sale.date)};
    });
    if (changed) {
      migratedSales.set(String(sale.id), next);
      statements.push(db.prepare("UPDATE sales SET items=? WHERE id=?").bind(JSON.stringify(next), sale.id));
    } else {
      migratedSales.set(String(sale.id), items);
    }
  }

  for (const ret of returnsResult.results || []) {
    const items = parsedItems(ret);
    if (!items) continue;
    let changed = false;
    const next = items.map(item => {
      if (!item || item.manual || !item.product || validSnapshot(item)) return item;
      changed = true;
      const sourceId = String(item.sourceSaleId || "");
      const sourceSale = sourceId ? salesById.get(sourceId) : null;
      const sourceItems = sourceSale ? (migratedSales.get(sourceId) || parsedItems(sourceSale) || []) : [];
      const match = sourceItems.find(s => !s.manual && String(s.product || "") === String(item.product));
      if (match && validSnapshot(match)) return {...item, costPrice: Math.max(0, Number(match.costPrice))};
      return {...item, costPrice: historicalCost(item.product, ret.date)};
    });
    if (changed) statements.push(db.prepare("UPDATE returns SET items=? WHERE id=?").bind(JSON.stringify(next), ret.id));
  }

  for (let offset = 0; offset < statements.length; offset += 50) {
    await db.batch(statements.slice(offset, offset + 50));
  }
  await megaSet(db, migrationKey, true);
}

async function megaSummary(db, user) {
  // Return only records permitted by this session's server-side RBAC grants.
  const canSales = altinCan(user, 'sales.view');
  const canPurchases = altinCan(user, 'purchases.view');
  const canStock = altinCan(user, 'stock.view');
  const canReturns = altinCan(user, 'returns.view');
  const canDebts = altinCan(user, 'debts.view');
  const canAudit = altinCan(user, 'audit.view');
  const canUsers = altinCan(user, 'users.view');
  const canProducts = canPurchases || canStock || canSales;

  const empty = {results:[]};
  const [products, sales, purchases, returns, debts, moves, audit, users] = await Promise.all([
    canProducts ? db.prepare("SELECT * FROM products ORDER BY name COLLATE NOCASE").all() : Promise.resolve(empty),
    canSales ? db.prepare("SELECT * FROM sales ORDER BY date DESC").all() : Promise.resolve(empty),
    canPurchases ? db.prepare("SELECT * FROM purchases ORDER BY date DESC").all() : Promise.resolve(empty),
    canReturns ? db.prepare("SELECT * FROM returns ORDER BY date DESC").all() : Promise.resolve(empty),
    canDebts ? db.prepare("SELECT * FROM debts ORDER BY date DESC").all() : Promise.resolve(empty),
    canStock ? db.prepare("SELECT * FROM stock_movements ORDER BY date DESC LIMIT 1000").all() : Promise.resolve(empty),
    canAudit ? db.prepare("SELECT * FROM audit_logs ORDER BY date DESC LIMIT 500").all() : Promise.resolve(empty),
    canUsers ? db.prepare("SELECT id,username,name,role,permissions,active,date FROM altin_users ORDER BY username").all() : Promise.resolve(empty)
  ]);

  const safeProducts = (products.results || []).map(p => canPurchases ? p : {...p, buy:null});
  const safeDebts = canDebts ? (debts.results || []).filter(d => canPurchases || !(String(d.id || '').startsWith('purchase-') || String(d.note || '').includes('قەرزی کڕین'))) : [];
  return {
    products: safeProducts,
    sales: canSales ? parseItems(sales) : [],
    purchases: canPurchases ? (purchases.results || []) : [],
    returns: canReturns ? parseItems(returns) : [],
    debts: safeDebts,
    movements: canStock ? (moves.results || []) : [],
    audit: canAudit ? (audit.results || []) : [],
    users: canUsers ? (users.results || []) : []
  };
}

async function megaAuth(db, body, json) {
  const username=String(body?.username||"").trim();
  const password=String(body?.password||"");
  const u=await db.prepare("SELECT id,username,name,role,permissions,active FROM altin_users WHERE username=? AND password=?")
    .bind(username,password).first();
  if (!u || !u.active) return json({success:false,error:"ناوی بەکارهێنەر یان وشەی نهێنی هەڵەیە"},401);
  return json({success:true,user:{...u,permissions:JSON.parse(u.permissions||"[]")}});
}

async function megaReturnCheck(db, body, json) {
  const saleId=String(body?.saleId||"").trim();
  if (!saleId) return null;
  const sale=await db.prepare("SELECT id,date FROM sales WHERE id=?").bind(saleId).first();
  if (!sale) return json({error:"فاتورەی بنەڕەت نەدۆزرایەوە"},404);
  const created=new Date(sale.date).getTime();
  const now=Date.now();
  const allowedDays=await megaGet(db,"returnDays",3);
  const days=(now-created)/86400000;
  if (days>Number(allowedDays||3)) return json({error:`گەڕاندنەوە تەنیا تا ${Number(allowedDays||3)} ڕۆژ دوای فرۆشتن ڕێگەپێدراوە.`},409);
  return null;
}
