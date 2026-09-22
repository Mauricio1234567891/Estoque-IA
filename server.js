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
const {Pool}=pg; const db=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.NODE_ENV==='production'?{rejectUnauthorized:false}:undefined}); const app=express();
const __dirname=path.dirname(fileURLToPath(import.meta.url));
async function migrate(){await db.query('CREATE TABLE IF NOT EXISTS schema_migrations(filename text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');for(const f of ['001_init.sql','002_v11.sql','003_v12.sql']){const done=(await db.query('SELECT 1 FROM schema_migrations WHERE filename=$1',[f])).rowCount;if(done)continue;const sql=fs.readFileSync(path.join(__dirname,f),'utf8');const c=await db.connect();try{await c.query('BEGIN');await c.query(sql);await c.query('INSERT INTO schema_migrations(filename) VALUES($1)',[f]);await c.query('COMMIT')}catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}}}
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
app.get('/health',(req,res)=>res.json({ok:true,version:'14.0.0',database:'postgresql'}));
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
app.post('/sales/:id/cancel',auth,role('ADMIN','GERENTE'),async(req,res)=>{const c=await db.connect();try{await c.query('BEGIN');const sale=(await c.query("SELECT * FROM sales WHERE id=$1 AND tenant_id=$2 AND status='COMPLETED' FOR UPDATE",[req.params.id,req.user.tenant_id])).rows[0];if(!sale)throw new Error('sale_not_found');const items=(await c.query('SELECT * FROM sale_items WHERE sale_id=$1',[sale.id])).rows;for(const i of items){await c.query('UPDATE products SET stock=stock+$1 WHERE id=$2 AND tenant_id=$3',[i.qty,i.product_id,req.user.tenant_id]);await c.query("INSERT INTO inventory_movements(tenant_id,branch_id,product_id,user_id,kind,qty,reference_id) VALUES($1,$2,$3,$4,'SALE_CANCEL',$5,$6)",[req.user.tenant_id,sale.branch_id,i.product_id,req.user.sub,i.qty,sale.id])}await c.query("UPDATE sales SET status='CANCELLED',cancelled_at=now() WHERE id=$1",[sale.id]);await c.query("UPDATE receivables SET status='CANCELLED' WHERE sale_id=$1 AND tenant_id=$2",[sale.id,req.user.tenant_id]);await c.query('COMMIT');await audit(req.user,'SALE_CANCELLED',{sale_id:sale.id});res.json({ok:true})}catch(e){await c.query('ROLLBACK');res.status(400).json({error:e.message})}finally{c.release()}});

const PUBLIC_PLANS={BASICO:{name:'Básico',amount:49.90,limits:PLAN_LIMITS.BASICO},PRO:{name:'PRO',amount:99.90,limits:PLAN_LIMITS.PRO},PREMIUM:{name:'Premium',amount:199.90,limits:PLAN_LIMITS.PREMIUM}};
app.get('/billing/plans',(req,res)=>res.json(PUBLIC_PLANS));
app.get('/billing/subscription',auth,async(req,res)=>{const t=(await db.query('SELECT plan,status,trial_ends_at,current_period_end,billing_provider,provider_subscription_id FROM tenants WHERE id=$1',[req.user.tenant_id])).rows[0];res.json({...t,limits:PLAN_LIMITS[(t.plan||'BASICO').toUpperCase()]||PLAN_LIMITS.BASICO})});
app.post('/billing/checkout',auth,role('ADMIN'),async(req,res)=>{const plan=String(req.body?.plan||'').toUpperCase();if(!PUBLIC_PLANS[plan])return res.status(400).json({error:'invalid_plan'});const email=(await db.query('SELECT email FROM users WHERE id=$1',[req.user.sub])).rows[0]?.email;const payerEmail=process.env.MP_TEST_PAYER_EMAIL||email;if(!process.env.MP_ACCESS_TOKEN){return res.status(503).json({error:'billing_not_configured',message:'Cobrança real ainda não configurada.'})}try{const body={reason:`Estoque IA ${PUBLIC_PLANS[plan].name}`,external_reference:req.user.tenant_id,payer_email:payerEmail,auto_recurring:{frequency:1,frequency_type:'months',transaction_amount:PUBLIC_PLANS[plan].amount,currency_id:'BRL'},back_url:process.env.APP_URL||'http://localhost:8080',status:'pending'};const r=await fetch('https://api.mercadopago.com/preapproval',{method:'POST',headers:{Authorization:`Bearer ${process.env.MP_ACCESS_TOKEN}`,'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await r.json();if(!r.ok){console.error('[MercadoPago checkout]',{http_status:r.status,error:data?.error||null,message:data?.message||null,cause:Array.isArray(data?.cause)?data.cause.map(c=>({code:c?.code||null,description:c?.description||null})):null});throw new Error(data?.message||data?.error||`provider_http_${r.status}`);}await db.query("UPDATE tenants SET plan=$1,status='PENDING',billing_provider='MERCADO_PAGO',provider_subscription_id=$2 WHERE id=$3",[plan,data.id,req.user.tenant_id]);await db.query('INSERT INTO billing_events(tenant_id,provider,event_type,provider_event_id,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',[req.user.tenant_id,'MERCADO_PAGO','checkout_created',data.id,data]);res.json({mode:'mercado_pago',subscription_id:data.id,checkout_url:data.init_point||null,status:data.status})}catch(e){console.error('[Billing checkout error]',{message:e?.message||'unknown_error'});res.status(502).json({error:'billing_provider_error',message:e?.message||'provider_error'})}});
app.post('/billing/cancel',auth,role('ADMIN'),async(req,res)=>{const t=(await db.query('SELECT provider_subscription_id,billing_provider FROM tenants WHERE id=$1',[req.user.tenant_id])).rows[0];if(t?.billing_provider==='MERCADO_PAGO'&&t.provider_subscription_id&&process.env.MP_ACCESS_TOKEN){await fetch(`https://api.mercadopago.com/preapproval/${t.provider_subscription_id}`,{method:'PUT',headers:{Authorization:`Bearer ${process.env.MP_ACCESS_TOKEN}`,'Content-Type':'application/json'},body:JSON.stringify({status:'cancelled'})})}await db.query("UPDATE tenants SET status='CANCELLED' WHERE id=$1",[req.user.tenant_id]);await audit(req.user,'SUBSCRIPTION_CANCELLED');res.json({ok:true})});
app.post('/webhooks/mercadopago',async(req,res)=>{const eventId=String(req.query?.['data.id']||req.query?.data_id||req.body?.data?.id||req.body?.id||'');const type=String(req.body?.type||req.body?.topic||'unknown');if(!eventId)return res.status(200).json({ok:true});if(!process.env.MP_WEBHOOK_SECRET)return res.status(503).json({error:'webhook_not_configured'});const xSignature=String(req.headers['x-signature']||'');const xRequestId=String(req.headers['x-request-id']||'');const parts=Object.fromEntries(xSignature.split(',').map(p=>p.trim().split('=',2)).filter(x=>x.length===2));const ts=parts.ts||'',v1=parts.v1||'';const dataId=eventId.toLowerCase();const manifest=`id:${dataId};request-id:${xRequestId};ts:${ts};`;const expected=crypto.createHmac('sha256',process.env.MP_WEBHOOK_SECRET).update(manifest).digest('hex');const valid=v1.length===expected.length&&crypto.timingSafeEqual(Buffer.from(v1),Buffer.from(expected));if(!xSignature||!xRequestId||!ts||!v1||!valid)return res.status(401).json({error:'invalid_webhook_signature'});const ins=await db.query("INSERT INTO billing_events(provider,event_type,provider_event_id,payload) VALUES('MERCADO_PAGO',$1,$2,$3) ON CONFLICT(provider,provider_event_id,event_type) DO NOTHING RETURNING id",[type,eventId,req.body]);if(!ins.rowCount)return res.json({ok:true,duplicate:true});try{if(type.includes('subscription_preapproval')&&process.env.MP_ACCESS_TOKEN){const r=await fetch(`https://api.mercadopago.com/preapproval/${eventId}`,{headers:{Authorization:`Bearer ${process.env.MP_ACCESS_TOKEN}`}});const d=await r.json();const tenantId=d.external_reference;const map={authorized:'ACTIVE',paused:'PAST_DUE',cancelled:'CANCELLED',pending:'PENDING'};if(tenantId)await db.query("UPDATE tenants SET status=$1,provider_subscription_id=$2,current_period_end=CASE WHEN $1='ACTIVE' THEN now()+interval '30 days' ELSE current_period_end END WHERE id=$3",[map[d.status]||'PENDING',d.id,tenantId])}await db.query('UPDATE billing_events SET processed_at=now() WHERE provider=$1 AND provider_event_id=$2 AND event_type=$3',['MERCADO_PAGO',eventId,type]);res.json({ok:true})}catch(e){res.status(500).json({error:'webhook_processing_failed'})}});
app.get('/master/metrics',auth,role('ADMIN'),async(req,res)=>{if(!process.env.MASTER_TENANT_ID||req.user.tenant_id!==process.env.MASTER_TENANT_ID)return res.status(403).json({error:'master_only'});const x=(await db.query(`SELECT count(*)::int tenants,count(*) FILTER(WHERE status='ACTIVE')::int active,count(*) FILTER(WHERE status='TRIAL')::int trials,count(*) FILTER(WHERE status IN ('PAST_DUE','CANCELLED'))::int at_risk,COALESCE(sum(CASE plan WHEN 'BASICO' THEN 49.9 WHEN 'PRO' THEN 99.9 WHEN 'PREMIUM' THEN 199.9 ELSE 0 END) FILTER(WHERE status='ACTIVE'),0) mrr FROM tenants`)).rows[0];res.json(x)});

app.get('/me',auth,async(req,res)=>{const tenant=(await db.query('SELECT id,name,plan,status FROM tenants WHERE id=$1',[req.user.tenant_id])).rows[0];res.json({user:req.user,tenant})});
app.get('/branches',auth,async(req,res)=>res.json((await db.query('SELECT id,name FROM branches WHERE tenant_id=$1 ORDER BY name',[req.user.tenant_id])).rows));
app.get('/products',auth,async(req,res)=>res.json((await db.query('SELECT * FROM products WHERE tenant_id=$1 AND active=true ORDER BY name LIMIT 2000',[req.user.tenant_id])).rows));
app.post('/products',auth,subscription,(req,res,next)=>enforceLimit('products',req,res,next),role('ADMIN','GERENTE'),async(req,res)=>{const S=z.object({sku:z.string().min(1),barcode:z.string().optional(),name:z.string().min(1),price:z.coerce.number().nonnegative(),cost:z.coerce.number().nonnegative().default(0),stock:z.coerce.number().default(0),min_stock:z.coerce.number().default(0)});const x=S.safeParse(req.body);if(!x.success)return res.status(400).json({error:x.error.flatten()});const v=x.data;try{const p=(await db.query('INSERT INTO products(tenant_id,sku,barcode,name,price,cost,stock,min_stock) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[req.user.tenant_id,v.sku,v.barcode||null,v.name,v.price,v.cost,v.stock,v.min_stock])).rows[0];await audit(req.user,'PRODUCT_CREATED',{product_id:p.id,sku:p.sku});res.status(201).json(p)}catch{return res.status(409).json({error:'sku_already_exists'})}});
app.patch('/products/:id',auth,role('ADMIN','GERENTE'),async(req,res)=>{const S=z.object({name:z.string().min(1).optional(),price:z.coerce.number().nonnegative().optional(),cost:z.coerce.number().nonnegative().optional(),min_stock:z.coerce.number().nonnegative().optional(),barcode:z.string().nullable().optional()});const x=S.safeParse(req.body);if(!x.success)return res.status(400).json({error:x.error.flatten()});let p=(await db.query(`UPDATE products SET name=COALESCE($1,name),price=COALESCE($2,price),cost=COALESCE($3,cost),min_stock=COALESCE($4,min_stock),barcode=COALESCE($5,barcode) WHERE id=$6 AND tenant_id=$7 RETURNING *`,[x.data.name??null,x.data.price??null,x.data.cost??null,x.data.min_stock??null,x.data.barcode??null,req.params.id,req.user.tenant_id])).rows[0];if(!p)return res.status(404).json({error:'not_found'});await audit(req.user,'PRODUCT_UPDATED',{product_id:p.id});res.json(p)});
app.post('/sales',auth,subscription,async(req,res)=>{const S=z.object({branch_id:z.string().uuid(),payment_method:z.string().min(1),items:z.array(z.object({product_id:z.string().uuid(),qty:z.coerce.number().positive()})).min(1)});const x=S.safeParse(req.body);if(!x.success)return res.status(400).json({error:x.error.flatten()});const c=await db.connect();try{await c.query('BEGIN');const branch=(await c.query('SELECT id FROM branches WHERE id=$1 AND tenant_id=$2',[x.data.branch_id,req.user.tenant_id])).rows[0];if(!branch)throw new Error('invalid_branch');let total=0,rows=[];for(const i of x.data.items){const p=(await c.query('SELECT * FROM products WHERE id=$1 AND tenant_id=$2 FOR UPDATE',[i.product_id,req.user.tenant_id])).rows[0];if(!p||Number(p.stock)<i.qty)throw new Error('insufficient_stock');total+=Number(p.price)*i.qty;rows.push([p,i.qty])}const sale=(await c.query('INSERT INTO sales(tenant_id,branch_id,user_id,total,payment_method) VALUES($1,$2,$3,$4,$5) RETURNING *',[req.user.tenant_id,x.data.branch_id,req.user.sub,total,x.data.payment_method])).rows[0];for(const [p,qty] of rows){await c.query('INSERT INTO sale_items(sale_id,product_id,qty,unit_price,unit_cost) VALUES($1,$2,$3,$4,$5)',[sale.id,p.id,qty,p.price,p.cost]);await c.query('UPDATE products SET stock=stock-$1 WHERE id=$2 AND tenant_id=$3',[qty,p.id,req.user.tenant_id]);await c.query("INSERT INTO inventory_movements(tenant_id,branch_id,product_id,user_id,kind,qty,reference_id) VALUES($1,$2,$3,$4,'SALE',$5,$6)",[req.user.tenant_id,x.data.branch_id,p.id,req.user.sub,-qty,sale.id])}await c.query('COMMIT');await audit(req.user,'SALE_COMPLETED',{sale_id:sale.id,total});res.status(201).json(sale)}catch(e){await c.query('ROLLBACK');res.status(400).json({error:e.message})}finally{c.release()}});
app.get('/sales',auth,async(req,res)=>{const q=await db.query(`SELECT s.id,s.total,s.payment_method,s.status,s.created_at,u.name user_name,b.name branch_name FROM sales s JOIN users u ON u.id=s.user_id JOIN branches b ON b.id=s.branch_id WHERE s.tenant_id=$1 ORDER BY s.created_at DESC LIMIT 200`,[req.user.tenant_id]);res.json(q.rows)});
app.get('/reports/dashboard',auth,async(req,res)=>{const k=(await db.query("SELECT COALESCE(sum(total),0) revenue,count(*) sales,COALESCE(avg(total),0) ticket FROM sales WHERE tenant_id=$1 AND status='COMPLETED' AND created_at>=date_trunc('month',now())",[req.user.tenant_id])).rows[0];const low=(await db.query('SELECT count(*)::int low_stock FROM products WHERE tenant_id=$1 AND active=true AND stock<=min_stock',[req.user.tenant_id])).rows[0];res.json({...k,...low})});
app.get('/audit',auth,role('ADMIN'),async(req,res)=>res.json((await db.query('SELECT action,metadata,created_at FROM audit_logs WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 200',[req.user.tenant_id])).rows));
app.use(express.static(__dirname));app.get('/',(req,res)=>res.sendFile(path.join(__dirname,'index.html')));
app.use((e,req,res,next)=>{console.error(e);res.status(500).json({error:'internal_error'})});
app.get('/admin/mp-whoami', auth, role('ADMIN'), async (req,res)=>{
  try{
    const r=await fetch('https://api.mercadopago.com/users/me',{
      headers:{Authorization:`Bearer ${process.env.MP_ACCESS_TOKEN}`}
    });
    const data=await r.json();

    console.log('[MP whoami]',{
      http_status:r.status,
      id:data?.id||null,
      nickname:data?.nickname||null,
      site_id:data?.site_id||null
    });

    res.status(r.status).json({
      http_status:r.status,
      id:data?.id||null,
      nickname:data?.nickname||null,
      site_id:data?.site_id||null,
      error:data?.error||null,
      message:data?.message||null
    });
  }catch(e){
    res.status(500).json({error:'mp_whoami_failed'});
  }
});
app.get('/admin/create-mp-test-user', auth, role('ADMIN'), async (req, res) => {
  try {
    if (!process.env.MP_ACCESS_TOKEN) {
      return res.status(503).json({
        error: 'MP_ACCESS_TOKEN_not_configured'
      });
    }

    const r = await fetch('https://api.mercadopago.com/users/test', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        site_id: 'MLB',
        description: 'Buyer Estoque IA'
      })
    });

    const data = await r.json();

    if (!r.ok) {
      console.error('[MP create test user]', { http_status: r.status, error: data?.error || null, message: data?.message || null, cause: data?.cause || null });
      return res.status(r.status).json({
        error: data?.error || 'mercadopago_error',
        message: data?.message || null
      });
    }

    return res.json({
      id: data.id,
      nickname: data.nickname,
      email: data.email,
      site_status: data.site_status
    });

  } catch (e) {
    console.error('[MP test user]', e?.message);
    return res.status(500).json({
      error: 'test_user_creation_failed'
    });
  }
});
app.get('/admin/test-mp-plan',auth,role('ADMIN'),async(req,res)=>{
  try{
    const body={
      reason:'Estoque IA PRO TESTE',
      auto_recurring:{
        frequency:1,
        frequency_type:'months',
        transaction_amount:99.90,
        currency_id:'BRL'
      },
      back_url:process.env.APP_URL||'https://estoque-ia-v12.onrender.com'
    };

    const r=await fetch('https://api.mercadopago.com/preapproval_plan',{
      method:'POST',
      headers:{
        Authorization:`Bearer ${process.env.MP_ACCESS_TOKEN}`,
        'Content-Type':'application/json'
      },
      body:JSON.stringify(body)
    });

    const data=await r.json();

    console.log('[MP plan test]',{
      http_status:r.status,
      id:data?.id||null,
      status:data?.status||null,
      message:data?.message||null
    });

    return res.status(r.status).json({
      http_status:r.status,
      id:data?.id||null,
      status:data?.status||null,
      init_point:data?.init_point||null,
      error:data?.error||null,
      message:data?.message||null
    });
  }catch(e){
    console.error('[MP plan test error]',e?.message);
    return res.status(500).json({
      error:'mp_plan_test_failed'
    });
  }
});
app.get('/admin/test-mp-subscriptions',auth,role('ADMIN'),async(req,res)=>{
  try{
    const r=await fetch('https://api.mercadopago.com/preapproval/search?status=authorized',{
      headers:{Authorization:`Bearer ${process.env.MP_ACCESS_TOKEN}`}
    });
    const data=await r.json();

    return res.status(r.status).json({
      http_status:r.status,
      results:(data.results||[]).map(x=>({
        id:x.id,
        status:x.status,
        reason:x.reason,
        preapproval_plan_id:x.preapproval_plan_id,
        external_reference:x.external_reference,
        payer_id:x.payer_id,
        next_payment_date:x.next_payment_date
      }))
    });
  }catch(e){
    return res.status(500).json({
      error:'mp_subscription_search_failed'
    });
  }
});

app.listen(Number(process.env.PORT||3000),()=>console.log('Estoque IA V14 API on port '+(process.env.PORT||3000)));
