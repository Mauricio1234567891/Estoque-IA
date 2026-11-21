import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import {z} from 'zod';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {fileURLToPath} from 'url';
if (process.env.NODE_ENV === 'production' &&
    (!process.env.DATABASE_URL || !process.env.JWT_SECRET)) {
  throw new Error('DATABASE_URL and JWT_SECRET are required in production.');
}
const {Pool}=pg; const db=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.NODE_ENV==='production'?{rejectUnauthorized:false}:undefined}); const app=express();
const __dirname=path.dirname(fileURLToPath(import.meta.url));
async function migrate(){await db.query('CREATE TABLE IF NOT EXISTS schema_migrations(filename text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');for(const f of ['001_init.sql','002_v11.sql','003_v12.sql','004_billing_sync.sql']){const done=(await db.query('SELECT 1 FROM schema_migrations WHERE filename=$1',[f])).rowCount;if(done)continue;const sql=fs.readFileSync(path.join(__dirname,f),'utf8');const c=await db.connect();try{await c.query('BEGIN');await c.query(sql);await c.query('INSERT INTO schema_migrations(filename) VALUES($1)',[f]);await c.query('COMMIT')}catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}}}
await migrate();
app.use(cors({origin:process.env.CORS_ORIGIN?.split(',')||true})); app.use(express.json({limit:'1mb'}));
const secret=process.env.JWT_SECRET||'DEV_ONLY_CHANGE_ME';
const token=u=>jwt.sign({sub:u.id||u.sub,tenant_id:u.tenant_id,role:u.role,name:u.name},secret,{expiresIn:'15m'});
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
async function issueSession(u){const raw=crypto.randomBytes(48).toString('hex');await db.query(`INSERT INTO refresh_sessions(tenant_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '30 days')`,[u.tenant_id,u.id||u.sub,sha(raw)]);return {access_token:token(u),refresh_token:raw};}
function auth(req,res,next){try{req.user=jwt.verify((req.headers.authorization||'').replace(/^Bearer\s+/i,''),secret);next()}catch{return res.status(401).json({error:'unauthorized'})}}
const role=(...r)=>(req,res,next)=>r.includes(req.user.role)?next():res.status(403).json({error:'forbidden'});
const audit=(u,a,m={})=>db.query('INSERT INTO audit_logs(tenant_id,user_id,action,metadata) VALUES($1,$2,$3,$4)',[u?.tenant_id||null,u?.sub||u?.id||null,a,m]).catch(()=>{});
const PLAN_LIMITS={BASICO:{products:500,users:2,branches:1},PRO:{products:5000,users:10,branches:5},PREMIUM:{products:50000,users:50,branches:30}};
async function subscription(req,res,next){const t=(await db.query('SELECT plan,status,trial_ends_at,current_period_end FROM tenants WHERE id=$1',[req.user.tenant_id])).rows[0];if(!t)return res.status(403).json({error:'tenant_not_found'});const ok=['ACTIVE','TRIAL'].includes(t.status)&&(!t.current_period_end||new Date(t.current_period_end)>new Date())&&(!t.trial_ends_at||t.status!=='TRIAL'||new Date(t.trial_ends_at)>new Date());if(!ok)return res.status(402).json({error:'subscription_required',status:t.status});req.subscription=t;next()}
async function enforceLimit(kind,req,res,next){const plan=(req.subscription?.plan||'BASICO').toUpperCase();const lim=(PLAN_LIMITS[plan]||PLAN_LIMITS.BASICO)[kind];const table={products:'products',users:'users',branches:'branches'}[kind];const n=Number((await db.query(`SELECT count(*) n FROM ${table} WHERE tenant_id=$1${kind==='products'?" AND active=true":kind==='users'?" AND active=true":''}`,[req.user.tenant_id])).rows[0].n);if(n>=lim)return res.status(403).json({error:'plan_limit_reached',resource:kind,limit:lim,plan});next()}
app.get('/health', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ ok: true, version: '14.0.0', database: 'postgresql' });
  } catch {
    res.status(503).json({ ok: false, error: 'database_unavailable' });
  }
});
app.post('/auth/register',async(req,res)=>{const S=z.object({company:z.string().min(2),name:z.string().min(2),email:z.string().email(),password:z.string().min(8),plan:z.enum(['BASICO','PRO','PREMIUM']).default('PRO')});const x=S.safeParse(req.body);if(!x.success)return res.status(400).json({error:x.error.flatten()});const c=await db.connect();try{await c.query('BEGIN');const t=(await c.query("INSERT INTO tenants(name,plan,status,trial_ends_at) VALUES($1,$2,'TRIAL',now()+interval '14 days') RETURNING *",[x.data.company,x.data.plan])).rows[0];const b=(await c.query("INSERT INTO branches(tenant_id,name) VALUES($1,'Matriz') RETURNING *",[t.id])).rows[0];const hash=await bcrypt.hash(x.data.password,12);const u=(await c.query("INSERT INTO users(tenant_id,name,email,password_hash,role) VALUES($1,$2,$3,$4,'ADMIN') RETURNING id,tenant_id,name,email,role",[t.id,x.data.name,x.data.email.toLowerCase(),hash])).rows[0];await c.query('COMMIT');res.status(201).json({...(await issueSession(u)),user:u,tenant:t,branch:b})}catch(e){await c.query('ROLLBACK');res.status(409).json({error:'registration_failed'})}finally{c.release()}});
app.post('/auth/login',async(req,res)=>{const {email,password}=req.body||{};const u=(await db.query('SELECT * FROM users WHERE lower(email)=lower($1) AND active=true LIMIT 1',[email])).rows[0];if(!u||!await bcrypt.compare(password||'',u.password_hash))return res.status(401).json({error:'invalid_credentials'});await audit(u,'LOGIN');res.json({...(await issueSession(u)),user:{id:u.id,tenant_id:u.tenant_id,name:u.name,email:u.email,role:u.role}})});

app.post('/auth/refresh',async(req,res)=>{const raw=req.body?.refresh_token;if(!raw)return res.status(400).json({error:'refresh_required'});const q=await db.query(`SELECT r.*,u.name,u.role,u.active FROM refresh_sessions r JOIN users u ON u.id=r.user_id WHERE r.token_hash=$1 AND r.revoked_at IS NULL AND r.expires_at>now()`,[sha(raw)]);const x=q.rows[0];if(!x||!x.active)return res.status(401).json({error:'invalid_refresh'});await db.query('UPDATE refresh_sessions SET revoked_at=now() WHERE id=$1',[x.id]);res.json(await issueSession({id:x.user_id,tenant_id:x.tenant_id,name:x.name,role:x.role}))});
app.post('/auth/logout',async(req,res)=>{if(req.body?.refresh_token)await db.query('UPDATE refresh_sessions SET revoked_at=now() WHERE token_hash=$1',[sha(req.body.refresh_token)]);res.json({ok:true})});
app.post('/auth/forgot-password',async(req,res)=>{const u=(await db.query('SELECT id FROM users WHERE lower(email)=lower($1) AND active=true LIMIT 1',[req.body?.email||''])).rows[0];if(u){const raw=crypto.randomBytes(32).toString('hex');await db.query(`INSERT INTO password_reset_tokens(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '30 minutes')`,[u.id,sha(raw)]);if(process.env.NODE_ENV!=='production')return res.json({ok:true,dev_reset_token:raw})}res.json({ok:true})});
app.post('/auth/reset-password',async(req,res)=>{const {token:raw,password}=req.body||{};if(!raw||!password||password.length<8)return res.status(400).json({error:'invalid_request'});const c=await db.connect();try{await c.query('BEGIN');const r=(await c.query(`SELECT * FROM password_reset_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE`,[sha(raw)])).rows[0];if(!r)throw new Error('invalid_token');await c.query('UPDATE users SET password_hash=$1 WHERE id=$2',[await bcrypt.hash(password,12),r.user_id]);await c.query('UPDATE password_reset_tokens SET used_at=now() WHERE id=$1',[r.id]);await c.query('UPDATE refresh_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL',[r.user_id]);await c.query('COMMIT');res.json({ok:true})}catch(e){await c.query('ROLLBACK');res.status(400).json({error:e.message})}finally{c.release()}});
app.get('/users',auth,role('ADMIN'),async(req,res)=>res.json((await db.query('SELECT id,name,email,role,active,created_at FROM users WHERE tenant_id=$1 ORDER BY name',[req.user.tenant_id])).rows));
app.post('/users',auth,subscription,(req,res,next)=>enforceLimit('users',req,res,next),role('ADMIN'),async(req,res)=>{const S=z.object({name:z.string().min(2),email:z.string().email(),password:z.string().min(8),role:z.enum(['ADMIN','GERENTE','CAIXA'])});const x=S.safeParse(req.body);if(!x.success)return res.status(400).json({error:x.error.flatten()});try{const u=(await db.query('INSERT INTO users(tenant_id,name,email,password_hash,role) VALUES($1,$2,$3,$4,$5) RETURNING id,name,email,role,active',[req.user.tenant_id,x.data.name,x.data.email.toLowerCase(),await bcrypt.hash(x.data.password,12),x.data.role])).rows[0];await audit(req.user,'USER_CREATED',{user_id:u.id,role:u.role});res.status(201).json(u)}catch{res.status(409).json({error:'email_exists'})}});
app.patch('/users/:id',auth,role('ADMIN'),async(req,res)=>{const S=z.object({role:z.enum(['ADMIN','GERENTE','CAIXA']).optional(),active:z.boolean().optional()});const x=S.safeParse(req.body);if(!x.success)return res.status(400).json({error:x.error.flatten()});const u=(await db.query('UPDATE users SET role=COALESCE($1,role),active=COALESCE($2,active) WHERE id=$3 AND tenant_id=$4 RETURNING id,name,email,role,active',[x.data.role??null,x.data.active??null,req.params.id,req.user.tenant_id])).rows[0];if(!u)return res.status(404).json({error:'not_found'});res.json(u)});
app.get('/customers',auth,async(req,res)=>res.json((await db.query('SELECT * FROM customers WHERE tenant_id=$1 AND active=true ORDER BY name',[req.user.tenant_id])).rows));
app.post('/customers',auth,async(req,res)=>{const S=z.object({name:z.string().min(2),document:z.string().optional(),email:z.string().optional(),phone:z.string().optional()});const x=S.safeParse(req.body);if(!x.success)return res.status(400).json({error:x.error.flatten()});res.status(201).json((await db.query('INSERT INTO customers(tenant_id,name,document,email,phone) VALUES($1,$2,$3,$4,$5) RETURNING *',[req.user.tenant_id,x.data.name,x.data.document||null,x.data.email||null,x.data.phone||null])).rows[0])});
app.post('/cash/open',auth,async(req,res)=>{const {branch_id,opening_amount=0}=req.body||{};const exists=(await db.query("SELECT id FROM cash_sessions WHERE tenant_id=$1 AND user_id=$2 AND status='OPEN'",[req.user.tenant_id,req.user.sub])).rows[0];if(exists)return res.status(409).json({error:'cash_already_open'});const x=(await db.query("INSERT INTO cash_sessions(tenant_id,branch_id,user_id,opening_amount) SELECT $1,id,$3,$4 FROM branches WHERE id=$2 AND tenant_id=$1 RETURNING *",[req.user.tenant_id,branch_id,req.user.sub,opening_amount])).rows[0];if(!x)return res.status(400).json({error:'invalid_branch'});res.status(201).json(x)});
app.post('/cash/:id/movement',auth,async(req,res)=>{const S=z.object({kind:z.enum(['SUPPLY','WITHDRAWAL']),amount:z.coerce.number().positive(),note:z.string().optional()});const x=S.safeParse(req.body);if(!x.success)return res.status(400).json({error:x.error.flatten()});const own=(await db.query("SELECT id FROM cash_sessions WHERE id=$1 AND tenant_id=$2 AND status='OPEN'",[req.params.id,req.user.tenant_id])).rows[0];if(!own)return res.status(404).json({error:'cash_not_open'});res.status(201).json((await db.query('INSERT INTO cash_movements(tenant_id,cash_session_id,user_id,kind,amount,note) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',[req.user.tenant_id,req.params.id,req.user.sub,x.data.kind,x.data.amount,x.data.note||null])).rows[0])});
app.post('/cash/:id/close',auth,async(req,res)=>{const x=(await db.query("UPDATE cash_sessions SET status='CLOSED',closing_amount=$1,closed_at=now() WHERE id=$2 AND tenant_id=$3 AND status='OPEN' RETURNING *",[req.body?.closing_amount||0,req.params.id,req.user.tenant_id])).rows[0];if(!x)return res.status(404).json({error:'cash_not_open'});res.json(x)});
app.get('/receivables',auth,async(req,res)=>res.json((await db.query('SELECT r.*,c.name customer_name FROM receivables r LEFT JOIN customers c ON c.id=r.customer_id WHERE r.tenant_id=$1 ORDER BY r.created_at DESC',[req.user.tenant_id])).rows));
app.post('/receivables/:id/pay',auth,async(req,res)=>{const amount=Number(req.body?.amount||0);if(amount<=0)return res.status(400).json({error:'invalid_amount'});const r=(await db.query(`UPDATE receivables SET paid_amount=LEAST(amount,paid_amount+$1),status=CASE WHEN paid_amount+$1>=amount THEN 'PAID' ELSE 'OPEN' END WHERE id=$2 AND tenant_id=$3 RETURNING *`,[amount,req.params.id,req.user.tenant_id])).rows[0];if(!r)return res.status(404).json({error:'not_found'});res.json(r)});
app.post('/sales/:id/cancel',auth,role('ADMIN','GERENTE'),async(req,res)=>{const c=await db.connect();try{await c.query('BEGIN');const sale=(await c.query("SELECT * FROM sales WHERE id=$1 AND tenant_id=$2 AND status='COMPLETED' FOR UPDATE",[req.params.id,req.user.tenant_id])).rows[0];if(!sale)throw new Error('sale_not_found');const items=(await c.query('SELECT * FROM sale_items WHERE sale_id=$1 ORDER BY product_id',[sale.id])).rows;for(const i of items){await c.query('UPDATE products SET stock=stock+$1 WHERE id=$2 AND tenant_id=$3',[i.qty,i.product_id,req.user.tenant_id]);await c.query("INSERT INTO inventory_movements(tenant_id,branch_id,product_id,user_id,kind,qty,reference_id) VALUES($1,$2,$3,$4,'SALE_CANCEL',$5,$6)",[req.user.tenant_id,sale.branch_id,i.product_id,req.user.sub,i.qty,sale.id])}await c.query("UPDATE sales SET status='CANCELLED',cancelled_at=now() WHERE id=$1",[sale.id]);await c.query("UPDATE receivables SET status='CANCELLED' WHERE sale_id=$1 AND tenant_id=$2",[sale.id,req.user.tenant_id]);await c.query('COMMIT');await audit(req.user,'SALE_CANCELLED',{sale_id:sale.id});res.json({ok:true})}catch(e){await c.query('ROLLBACK');res.status(400).json({error:e.message})}finally{c.release()}});

const PUBLIC_PLANS={BASICO:{name:'Básico',amount:49.90,limits:PLAN_LIMITS.BASICO},PRO:{name:'PRO',amount:99.90,limits:PLAN_LIMITS.PRO},PREMIUM:{name:'Premium',amount:199.90,limits:PLAN_LIMITS.PREMIUM}};
app.get('/billing/plans',(req,res)=>res.json(PUBLIC_PLANS));
const mpProvider = 'MERCADO_PAGO';
const mpPlans = {
  BASICO: process.env.MP_PLAN_BASICO_ID,
  PRO: process.env.MP_PLAN_PRO_ID,
  PREMIUM: process.env.MP_PLAN_PREMIUM_ID
};
const mpEnabled = process.env.MP_CHECKOUT_ENABLED === 'true' &&
  Boolean(process.env.MP_ACCESS_TOKEN && process.env.MP_PUBLIC_KEY &&
    process.env.MP_WEBHOOK_SECRET && Object.values(mpPlans).some(Boolean));

class MercadoPagoError extends Error {
  constructor(status) {
    super('mercado_pago_request_failed');
    this.status = status;
  }
}

async function mpRequest(endpoint, method = 'GET', body) {
  const response = await fetch('https://api.mercadopago.com' + endpoint, {
    method,
    headers: {
      Authorization: 'Bearer ' + process.env.MP_ACCESS_TOKEN,
      'Content-Type': 'application/json',
      ...(process.env.MP_TEST_MODE === 'true' ? { 'X-scope': 'stage' } : {})
    },
    body: body && JSON.stringify(body),
    signal: AbortSignal.timeout(10_000)
  });
  if (!response.ok) throw new MercadoPagoError(response.status);
  return response.json();
}

const mpSubscriptionPath = id => '/preapproval/' + encodeURIComponent(id);
const mpDate = value => typeof value === 'string' && Number.isFinite(Date.parse(value))
  ? new Date(value) : null;
const mpStatus = new Map([
  ['pending', 'PENDING'], ['authorized', 'PENDING'], ['paused', 'PAST_DUE'],
  ['cancelled', 'CANCELLED'], ['canceled', 'CANCELLED']
]);

async function syncMpSubscription(data) {
  const [tenantId, checkoutId, ...extra] = String(data.external_reference ?? '').split(':');
  if (!z.string().uuid().safeParse(tenantId).success || extra.length ||
    typeof data.id !== 'string' || !data.id || !mpStatus.has(data.status)) return null;

  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const { rows: [tenant] } = await client.query(
      'SELECT * FROM tenants WHERE id=$1 FOR UPDATE', [tenantId]
    );
    const linked = tenant?.billing_provider === mpProvider && tenant.provider_subscription_id === data.id;
    const reserved = Boolean(tenant?.billing_checkout_id && tenant.billing_checkout_id === checkoutId);
    if (linked && tenant.billing_checkout_id && !reserved) {
      await client.query('COMMIT');
      return tenant;
    }
    const plan = reserved ? tenant.billing_checkout_plan : tenant?.plan;
    if ((!linked && !reserved) || !mpPlans[plan] || mpPlans[plan] !== data.preapproval_plan_id) {
      await client.query('COMMIT');
      return null;
    }
    const modified = mpDate(data.last_modified);
    if (linked && tenant.billing_provider_modified_at &&
        (!modified || modified < tenant.billing_provider_modified_at ||
          (tenant.status === 'CANCELLED' && mpStatus.get(data.status) !== 'CANCELLED'))) {
      await client.query('COMMIT');
      return tenant;
    }

    const charge = mpDate(data.summarized?.last_charged_date);
    const nextPayment = mpDate(data.next_payment_date);
    let paidThrough = linked ? tenant.current_period_end : null;
    let lastCharge = linked ? tenant.billing_last_charge_at : null;
    let status = mpStatus.get(data.status);
    if (data.status === 'authorized') {
      if (Number(data.summarized?.charged_quantity) > 0 && charge && nextPayment &&
          nextPayment > charge && (!lastCharge || charge > lastCharge)) {
        paidThrough = nextPayment;
        lastCharge = charge;
      }
      if (paidThrough && paidThrough > new Date()) status = 'ACTIVE';
      else if (paidThrough) status = 'PAST_DUE';
    }

    const result = await client.query(
      `UPDATE tenants SET plan=$2, status=$3, billing_provider=$4, provider_subscription_id=$5,
        current_period_end=$6, billing_last_charge_at=$7, billing_provider_modified_at=$8,
        billing_checkout_id=NULL, billing_checkout_plan=NULL
       WHERE id=$1 RETURNING plan, status, current_period_end, provider_subscription_id`,
      [tenantId, plan, status, mpProvider, data.id, paidThrough, lastCharge, modified]
    );
    await client.query('COMMIT');
    return result.rows[0];
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

app.get('/billing/config', (req, res) => {
  res.json({ public_key: mpEnabled ? process.env.MP_PUBLIC_KEY : null, enabled: mpEnabled });
});

app.get('/billing/subscription', auth, async (req, res, next) => {
  try {
    const { rows: [tenant] } = await db.query(
      `SELECT plan, status, trial_ends_at, current_period_end, billing_provider,
        provider_subscription_id, billing_checkout_id IS NOT NULL AS checkout_in_progress,
        provider_subscription_id IS NULL OR
          (status='CANCELLED' AND billing_provider_modified_at IS NOT NULL) AS can_checkout
       FROM tenants WHERE id=$1`, [req.user.tenant_id]
    );
    if (!tenant) return res.status(404).json({ error: 'tenant_not_found' });
    res.json({ ...tenant, limits: PLAN_LIMITS[tenant.plan] ?? PLAN_LIMITS.BASICO });
  } catch (error) {
    next(error);
  }
});

app.post('/billing/checkout', auth, role('ADMIN'), async (req, res, next) => {
  if (!mpEnabled) return res.status(503).json({ error: 'billing_not_configured' });
  const input = z.object({
    plan: z.enum(['BASICO', 'PRO', 'PREMIUM']),
    card_token_id: z.string().min(1).max(512)
  }).safeParse(req.body);
  if (!input.success) return res.status(400).json({ error: input.error.flatten() });

  const { plan, card_token_id } = input.data;
  if (!mpPlans[plan]) return res.status(503).json({ error: 'plan_not_configured' });

  const { tenant_id, sub: userId } = req.user;
  const attempt = crypto.randomUUID();
  let payerEmail;
  try {
    const { rows: [user] } = await db.query(
      'SELECT email FROM users WHERE id=$1 AND tenant_id=$2 AND active AND role=\'ADMIN\'',
      [userId, tenant_id]
    );
    if (!user) return res.status(403).json({ error: 'forbidden' });
    payerEmail = process.env.MP_TEST_MODE === 'true' && process.env.MP_TEST_PAYER_EMAIL
      ? process.env.MP_TEST_PAYER_EMAIL : user.email;

    const reservation = await db.query(
      `UPDATE tenants SET billing_checkout_id=$2, billing_checkout_plan=$3
       WHERE id=$1 AND billing_checkout_id IS NULL
         AND (provider_subscription_id IS NULL OR
           (status='CANCELLED' AND billing_provider_modified_at IS NOT NULL))
       RETURNING id`,
      [tenant_id, attempt, plan]
    );
    if (!reservation.rowCount) return res.status(409).json({ error: 'subscription_already_exists' });
  } catch (error) {
    return next(error);
  }

  try {
    const data = await mpRequest('/preapproval', 'POST', {
      preapproval_plan_id: mpPlans[plan],
      external_reference: tenant_id + ':' + attempt,
      payer_email: payerEmail,
      card_token_id,
      status: 'authorized'
    });
    const subscription = await syncMpSubscription(data);
    if (!subscription) return res.status(502).json({ error: 'subscription_confirmation_pending' });
    res.json({ mode: 'mercado_pago', subscription_id: data.id, status: subscription.status });
  } catch (error) {
    if (!(error instanceof MercadoPagoError) || ![400, 401, 403, 422].includes(error.status)) {
      return res.status(502).json({ error: 'subscription_confirmation_pending' });
    }
    try {
      await db.query(
        'UPDATE tenants SET billing_checkout_id=NULL, billing_checkout_plan=NULL WHERE id=$1 AND billing_checkout_id=$2',
        [tenant_id, attempt]
      );
      res.status(502).json({ error: 'billing_provider_error' });
    } catch (dbError) {
      next(dbError);
    }
  }
});

async function billingSubscriptionId(tenantId) {
  const { rows: [tenant] } = await db.query(
    'SELECT provider_subscription_id FROM tenants WHERE id=$1 AND billing_provider=$2',
    [tenantId, mpProvider]
  );
  return tenant?.provider_subscription_id;
}

const billingUpdate = cancel => async (req, res, next) => {
  if (!process.env.MP_ACCESS_TOKEN) return res.status(503).json({ error: 'billing_not_configured' });
  try {
    const id = await billingSubscriptionId(req.user.tenant_id);
    if (!id) return res.status(404).json({ error: 'subscription_not_found' });
    const endpoint = mpSubscriptionPath(id);
    const data = await mpRequest(endpoint);
    if (data.id !== id || String(data.external_reference ?? '').split(':')[0] !== req.user.tenant_id) {
      return res.status(409).json({ error: 'subscription_validation_failed' });
    }

    let confirmed = data;
    if (cancel && mpStatus.get(data.status) !== 'CANCELLED') {
      confirmed = await mpRequest(endpoint, 'PUT', { status: 'canceled' });
    }
    if (confirmed.id !== id ||
        String(confirmed.external_reference ?? '').split(':')[0] !== req.user.tenant_id ||
        (cancel && mpStatus.get(confirmed.status) !== 'CANCELLED')) {
      return res.status(502).json({ error: 'subscription_confirmation_pending' });
    }
    const subscription = await syncMpSubscription(confirmed);
    if (!subscription || (cancel && subscription.status !== 'CANCELLED')) {
      return res.status(409).json({ error: 'subscription_validation_failed' });
    }
    res.json({ ok: true, plan: subscription.plan, status: subscription.status });
  } catch (error) {
    if (error instanceof MercadoPagoError || error instanceof TypeError || error.name === 'TimeoutError') {
      return res.status(502).json({ error: 'billing_provider_error' });
    }
    next(error);
  }
};

app.post('/billing/sync', auth, role('ADMIN'), billingUpdate(false));
app.post('/billing/cancel', auth, role('ADMIN'), billingUpdate(true));

app.post('/webhooks/mercadopago', async (req, res) => {
  const id = req.query['data.id'];
  const type = req.body?.type;
  if (!['subscription_preapproval', 'subscription_authorized_payment'].includes(type)) return res.sendStatus(200);
  if (!process.env.MP_WEBHOOK_SECRET || !process.env.MP_ACCESS_TOKEN) return res.sendStatus(503);

  const requestId = req.get('x-request-id');
  const signature = new Map((req.get('x-signature') ?? '').split(',').map(part => part.trim().split('=')));
  const timestamp = signature.get('ts');
  const digest = signature.get('v1');
  if (typeof id !== 'string' || !/^[\da-z-]{1,128}$/i.test(id) || !requestId ||
      !/^\d{1,16}$/.test(timestamp ?? '') || !/^[a-f\d]{64}$/i.test(digest ?? '')) {
    return res.sendStatus(401);
  }
  const manifest = `id:${id.toLowerCase()};request-id:${requestId};ts:${timestamp};`;
  const expected = crypto.createHmac('sha256', process.env.MP_WEBHOOK_SECRET).update(manifest).digest();
  if (!crypto.timingSafeEqual(Buffer.from(digest, 'hex'), expected)) return res.sendStatus(401);

  try {
    const invoice = type === 'subscription_authorized_payment'
      ? await mpRequest('/authorized_payments/' + encodeURIComponent(id)) : null;
    if (invoice && (String(invoice.id) !== id || typeof invoice.preapproval_id !== 'string')) {
      return res.sendStatus(502);
    }

    const subscriptionId = invoice?.preapproval_id ?? id;
    const data = await mpRequest(mpSubscriptionPath(subscriptionId));
    if (data.id !== subscriptionId) return res.sendStatus(502);
    const lastCharge = mpDate(data.summarized?.last_charged_date);
    const debitDate = mpDate(invoice?.debit_date);
    if (invoice?.payment?.status === 'approved' && debitDate &&
        (!lastCharge || lastCharge < debitDate)) {
      return res.sendStatus(503);
    }
    await syncMpSubscription(data);
    res.sendStatus(200);
  } catch (error) {
    console.error('[Mercado Pago webhook]', error instanceof MercadoPagoError ? error.status : error.name);
    res.sendStatus(503);
  }
});

app.get('/master/metrics',auth,role('ADMIN'),async(req,res)=>{if(!process.env.MASTER_TENANT_ID||req.user.tenant_id!==process.env.MASTER_TENANT_ID)return res.status(403).json({error:'master_only'});const x=(await db.query(`SELECT count(*)::int tenants,count(*) FILTER(WHERE status='ACTIVE')::int active,count(*) FILTER(WHERE status='TRIAL')::int trials,count(*) FILTER(WHERE status IN ('PAST_DUE','CANCELLED'))::int at_risk,COALESCE(sum(CASE plan WHEN 'BASICO' THEN 49.9 WHEN 'PRO' THEN 99.9 WHEN 'PREMIUM' THEN 199.9 ELSE 0 END) FILTER(WHERE status='ACTIVE'),0) mrr FROM tenants`)).rows[0];res.json(x)});

app.get('/me',auth,async(req,res)=>{const tenant=(await db.query('SELECT id,name,plan,status FROM tenants WHERE id=$1',[req.user.tenant_id])).rows[0];res.json({user:req.user,tenant})});
app.get('/branches',auth,async(req,res)=>res.json((await db.query('SELECT id,name FROM branches WHERE tenant_id=$1 ORDER BY name',[req.user.tenant_id])).rows));
app.get('/products',auth,async(req,res)=>res.json((await db.query('SELECT * FROM products WHERE tenant_id=$1 AND active=true ORDER BY name LIMIT 2000',[req.user.tenant_id])).rows));
const newProduct = z.object({
  sku: z.string().min(1),
  barcode: z.string().optional(),
  name: z.string().min(1),
  price: z.coerce.number().nonnegative(),
  cost: z.coerce.number().nonnegative().default(0),
  stock: z.coerce.number().default(0),
  min_stock: z.coerce.number().default(0)
});

const importDecimal = (scale, max) => z.number().finite().min(-max).max(max)
  .refine(value => value === Math.round(value * scale) / scale, 'Casas decimais acima do limite.');

const importProduct = z.object({
  sku: z.string().trim().min(1).max(120),
  barcode: z.string().trim().max(120).optional(),
  nome: z.string().trim().min(1).max(250),
  preco: importDecimal(100, 999_999_999_999.99).refine(value => value >= 0),
  custo: importDecimal(100, 999_999_999_999.99).refine(value => value >= 0).default(0),
  saldo: importDecimal(1000, 99_999_999_999.999).default(0),
  min: importDecimal(1000, 99_999_999_999.999).refine(value => value >= 0).default(0)
}).transform(p => ({
  sku: p.sku, barcode: p.barcode, name: p.nome, price: p.preco,
  cost: p.custo, stock: p.saldo, min_stock: p.min
}));

async function saveNewProducts(tenantId, incoming, skipExisting) {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const { rows: [tenant] } = await client.query(
      'SELECT plan FROM tenants WHERE id=$1 FOR UPDATE', [tenantId]
    );
    const plan = tenant.plan.toUpperCase();
    const limit = (PLAN_LIMITS[plan] || PLAN_LIMITS.BASICO).products;
    const existing = (await client.query(
      'SELECT sku FROM products WHERE tenant_id=$1 AND sku=ANY($2::text[])',
      [tenantId, incoming.map(product => product.sku)]
    )).rows;
    const existingSkus = new Set(existing.map(product => product.sku));
    const products = incoming.filter(product => !existingSkus.has(product.sku));

    const { rows: [{ count }] } = await client.query(
      'SELECT count(*)::int AS count FROM products WHERE tenant_id=$1 AND active', [tenantId]
    );
    if (products.length > 0 && count + products.length > limit) {
      await client.query('ROLLBACK');
      return { error: 'plan_limit_reached', status: 403, resource: 'products', limit, plan };
    }
    if (!skipExisting && existing.length > 0) {
      await client.query('ROLLBACK');
      return { error: 'sku_already_exists', status: 409 };
    }

    const inserted = await client.query(
      `INSERT INTO products(tenant_id,sku,barcode,name,price,cost,stock,min_stock)
       SELECT $1, sku, nullif(barcode, ''), name, price, cost, stock, min_stock
       FROM jsonb_to_recordset($2::jsonb) AS p(
         sku text, barcode text, name text, price numeric, cost numeric, stock numeric, min_stock numeric
       )
       RETURNING *`,
      [tenantId, JSON.stringify(products)]
    );
    await client.query('COMMIT');
    return { rows: inserted.rows, skipped: existing.length };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

app.post('/products', auth, subscription, role('ADMIN', 'GERENTE'), async (req, res, next) => {
  const input = newProduct.safeParse(req.body);
  if (!input.success) return res.status(400).json({ error: input.error.flatten() });

  try {
    const { status, rows, ...result } = await saveNewProducts(req.user.tenant_id, [input.data], false);
    if (status) return res.status(status).json(result);
    const [product] = rows;
    await audit(req.user, 'PRODUCT_CREATED', { product_id: product.id, sku: product.sku });
    res.status(201).json(product);
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'sku_already_exists' });
    next(error);
  }
});

app.post('/products/import-offline', auth, subscription, role('ADMIN'), async (req, res, next) => {
  const input = z.object({ produtos: z.array(importProduct).min(1).max(5000) }).safeParse(req.body);
  if (!input.success) {
    const issue = input.error.issues[0];
    return res.status(400).json({
      error: 'invalid_offline_products',
      row: Number.isInteger(issue.path[1]) ? issue.path[1] + 1 : undefined,
      field: issue.path[2]
    });
  }
  const seen = new Set();
  for (const [index, product] of input.data.produtos.entries()) {
    if (seen.has(product.sku)) {
      return res.status(400).json({ error: 'duplicate_import_sku', row: index + 1 });
    }
    seen.add(product.sku);
  }

  try {
    const { status, rows, skipped, ...result } = await saveNewProducts(req.user.tenant_id, input.data.produtos, true);
    if (status) return res.status(status).json(result);
    const summary = { imported: rows.length, skipped };
    if (rows.length) await audit(req.user, 'OFFLINE_PRODUCTS_IMPORTED', summary);
    res.status(rows.length ? 201 : 200).json(summary);
  } catch (error) {
    next(error);
  }
});
app.patch('/products/:id',auth,role('ADMIN','GERENTE'),async(req,res)=>{const S=z.object({name:z.string().min(1).optional(),price:z.coerce.number().nonnegative().optional(),cost:z.coerce.number().nonnegative().optional(),min_stock:z.coerce.number().nonnegative().optional(),barcode:z.string().nullable().optional()});const x=S.safeParse(req.body);if(!x.success)return res.status(400).json({error:x.error.flatten()});let p=(await db.query(`UPDATE products SET name=COALESCE($1,name),price=COALESCE($2,price),cost=COALESCE($3,cost),min_stock=COALESCE($4,min_stock),barcode=COALESCE($5,barcode) WHERE id=$6 AND tenant_id=$7 RETURNING *`,[x.data.name??null,x.data.price??null,x.data.cost??null,x.data.min_stock??null,x.data.barcode??null,req.params.id,req.user.tenant_id])).rows[0];if(!p)return res.status(404).json({error:'not_found'});await audit(req.user,'PRODUCT_UPDATED',{product_id:p.id});res.json(p)});
const saleRequest = z.object({
  branch_id: z.string().uuid(),
  payment_method: z.string().min(1),
  items: z.array(z.object({
    product_id: z.string().uuid(),
    qty: z.coerce.number().positive().max(99_999_999_999.999)
      .refine(qty => qty === Math.round(qty * 1000) / 1000, {
        message: 'Use até três casas decimais para a quantidade.'
      })
  })).min(1)
});

app.post('/sales', auth, subscription, async (req, res, next) => {
  const request = saleRequest.safeParse(req.body);
  if (!request.success) return res.status(400).json({ error: request.error.flatten() });

  const { branch_id, payment_method, items } = request.data;
  const { tenant_id, sub: userId } = req.user;
  const productIds = [...new Set(items.map(item => item.product_id.toLowerCase()))];
  let sale;
  let total = 0;

  try {
    const client = await db.connect();
    try {
      await client.query('BEGIN');
      const branch = await client.query(
        'SELECT id FROM branches WHERE id=$1 AND tenant_id=$2',
        [branch_id, tenant_id]
      );
      if (!branch.rowCount) throw new Error('invalid_branch');

      const products = await client.query(
        'SELECT id, stock, price, cost FROM products WHERE tenant_id=$1 AND id=ANY($2::uuid[]) ORDER BY id FOR UPDATE',
        [tenant_id, productIds]
      );
      const byId = new Map(products.rows.map(product => [product.id, {
        ...product,
        // Use thousandths to match PostgreSQL numeric(14,3).
        remaining: Math.round(Number(product.stock) * 1000)
      }]));

      const lines = [];
      for (const item of items) {
        const product = byId.get(item.product_id.toLowerCase());
        const units = Math.round(item.qty * 1000);
        if (!product || product.remaining < units) throw new Error('insufficient_stock');

        product.remaining -= units;
        total += Number(product.price) * item.qty;
        lines.push({ product, qty: item.qty });
      }

      const created = await client.query(
        'INSERT INTO sales(tenant_id,branch_id,user_id,total,payment_method) VALUES($1,$2,$3,$4,$5) RETURNING *',
        [tenant_id, branch_id, userId, total, payment_method]
      );
      [sale] = created.rows;

      for (const { product, qty } of lines) {
        await client.query(
          'INSERT INTO sale_items(sale_id,product_id,qty,unit_price,unit_cost) VALUES($1,$2,$3,$4,$5)',
          [sale.id, product.id, qty, product.price, product.cost]
        );
        await client.query(
          "INSERT INTO inventory_movements(tenant_id,branch_id,product_id,user_id,kind,qty,reference_id) VALUES($1,$2,$3,$4,'SALE',$5,$6)",
          [tenant_id, branch_id, product.id, userId, -qty, sale.id]
        );
      }
      for (const product of byId.values()) {
        await client.query(
          'UPDATE products SET stock=$1 WHERE id=$2 AND tenant_id=$3',
          [product.remaining / 1000, product.id, tenant_id]
        );
      }

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    if (['invalid_branch', 'insufficient_stock'].includes(error.message)) {
      return res.status(400).json({ error: error.message });
    }
    return next(error);
  }

  await audit(req.user, 'SALE_COMPLETED', { sale_id: sale.id, total });
  res.status(201).json(sale);
});
app.get('/sales',auth,async(req,res)=>{const q=await db.query(`SELECT s.id,s.total,s.payment_method,s.status,s.created_at,u.name user_name,b.name branch_name FROM sales s JOIN users u ON u.id=s.user_id JOIN branches b ON b.id=s.branch_id WHERE s.tenant_id=$1 ORDER BY s.created_at DESC LIMIT 200`,[req.user.tenant_id]);res.json(q.rows)});
app.get('/reports/dashboard',auth,async(req,res)=>{const k=(await db.query("SELECT COALESCE(sum(total),0) revenue,count(*) sales,COALESCE(avg(total),0) ticket FROM sales WHERE tenant_id=$1 AND status='COMPLETED' AND created_at>=date_trunc('month',now())",[req.user.tenant_id])).rows[0];const low=(await db.query('SELECT count(*)::int low_stock FROM products WHERE tenant_id=$1 AND active=true AND stock<=min_stock',[req.user.tenant_id])).rows[0];res.json({...k,...low})});
const inventoryFilters = z.object({
  q: z.string().trim().max(120).default(''),
  critical: z.enum(['0', '1']).default('0'),
  page: z.coerce.number().int().min(1).max(1_000_000).default(1)
});
const inventoryPageSize = 25;

app.get('/reports/inventory', auth, async (req, res, next) => {
  const filters = inventoryFilters.safeParse(req.query);
  if (!filters.success) return res.status(400).json({ error: filters.error.flatten() });

  const { q, critical, page } = filters.data;
  try {
    const { rows } = await db.query(
      `SELECT id, sku, barcode, name, stock, min_stock, stock <= min_stock AS critical
       FROM products
       WHERE tenant_id = $1 AND active
         AND ($2 = '' OR strpos(lower(name), lower($2)) > 0
                      OR strpos(lower(sku), lower($2)) > 0
                      OR strpos(lower(coalesce(barcode, '')), lower($2)) > 0)
         AND (NOT $3::boolean OR stock <= min_stock)
       ORDER BY name, sku, id
       LIMIT $4 OFFSET $5`,
      [req.user.tenant_id, q, critical === '1', inventoryPageSize + 1, (page - 1) * inventoryPageSize]
    );
    res.json({ items: rows.slice(0, inventoryPageSize), has_more: rows.length > inventoryPageSize });
  } catch (error) {
    next(error);
  }
});

app.get('/reports/inventory/:id/movements', auth, async (req, res, next) => {
  const id = z.string().uuid().safeParse(req.params.id);
  if (!id.success) return res.status(400).json({ error: 'invalid_product' });

  try {
    const { rows } = await db.query(
      `SELECT m.id, m.created_at, m.kind, m.qty, b.name AS branch_name
       FROM inventory_movements m
       JOIN branches b ON b.id = m.branch_id AND b.tenant_id = m.tenant_id
       WHERE m.tenant_id = $1 AND m.product_id = $2
       ORDER BY m.created_at DESC, m.id DESC
       LIMIT 50`,
      [req.user.tenant_id, id.data]
    );
    res.json(rows);
  } catch (error) {
    next(error);
  }
});

app.get('/audit',auth,role('ADMIN'),async(req,res)=>res.json((await db.query('SELECT action,metadata,created_at FROM audit_logs WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 200',[req.user.tenant_id])).rows));
app.get(['/', '/index.html'], (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/app.html', (req, res) => res.sendFile(path.join(__dirname, 'app.html')));
app.use((error, req, res, next) => {
  console.error(error.name);
  if (res.headersSent) return next(error);
  res.status(error.status === 400 ? 400 : 500).json({ error: 'request_failed' });
});
app.use((e,req,res,next)=>{console.error(e);res.status(500).json({error:'internal_error'})});
app.listen(Number(process.env.PORT||3000),()=>console.log('Estoque IA V14 API on port '+(process.env.PORT||3000)));
