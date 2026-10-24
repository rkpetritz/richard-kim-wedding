const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...headers}});
const encoder=new TextEncoder();
const hex=async value=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(value)))).map(x=>x.toString(16).padStart(2,'0')).join('');
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
const mac=async(secret,msg)=>{const k=await crypto.subtle.importKey('raw',encoder.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);return b64(await crypto.subtle.sign('HMAC',k,encoder.encode(msg)))};
const safeEqual=(a,b)=>{if(typeof a!=='string'||typeof b!=='string')return false;let diff=a.length^b.length;for(let i=0;i<Math.max(a.length,b.length);i++)diff|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);return diff===0};
const parseCookie=req=>Object.fromEntries((req.headers.get('Cookie')||'').split(';').map(s=>s.trim().split('=').map(decodeURIComponent)).filter(x=>x.length===2));
async function authorized(req,env){const token=parseCookie(req).rk_host||'';const [exp,sig]=token.split('.');if(!/^\d+$/.test(exp)||Number(exp)<Date.now()||!sig)return false;return safeEqual(sig,await mac(env.SESSION_SECRET,exp))}
const limit=(s,n)=>typeof s==='string'?s.trim().slice(0,n):'';
async function body(req){if(Number(req.headers.get('content-length')||0)>10000)throw Error('Too large');return await req.json()}
const fields=['kimName','kimInterac','richardName','richardZelle','richardPaypal','richardBank','richardRouting','richardAccount','richardAccountType'];
const defaults={kimName:'Kim',kimInterac:'',richardName:'Richard',richardZelle:'',richardPaypal:'',richardBank:'',richardRouting:'',richardAccount:'',richardAccountType:'Checking'};
export async function onRequest({request,env,params}){
 try{
  if(!env.DB||!env.SESSION_SECRET||!env.HOST_PASSCODE_1||!env.HOST_PASSCODE_2)return json({error:'Server not configured. Set D1 and three secrets.'},503);
  const url=new URL(request.url), path='/'+(Array.isArray(params.path)?params.path.join('/'):params.path||'');const method=request.method;
  if(method!=='GET'&&method!=='HEAD'){const origin=request.headers.get('Origin');if(origin!==url.origin)return json({error:'Invalid request origin'},403);if(!['application/json'].some(t=>(request.headers.get('Content-Type')||'').startsWith(t)))return json({error:'JSON required'},415)}
  if(path==='/login'&&method==='POST'){
   const ip=request.headers.get('CF-Connecting-IP')||'unknown';const key=await hex(ip+env.SESSION_SECRET);const now=Date.now();const prev=await env.DB.prepare('SELECT count,reset_at FROM login_attempts WHERE ip_hash=?').bind(key).first();if(prev&&prev.reset_at>now&&prev.count>=5)return json({error:'Too many attempts. Try again in 15 minutes.'},429);
   const data=await body(request);const code=limit(data.code,128);const good=safeEqual(code,env.HOST_PASSCODE_1)||safeEqual(code,env.HOST_PASSCODE_2);
   if(!good){const count=prev&&prev.reset_at>now?prev.count+1:1;await env.DB.prepare('INSERT INTO login_attempts (ip_hash,count,reset_at) VALUES (?,?,?) ON CONFLICT(ip_hash) DO UPDATE SET count=excluded.count,reset_at=excluded.reset_at').bind(key,count,now+900000).run();return json({error:'Invalid passcode'},401)}
   await env.DB.prepare('DELETE FROM login_attempts WHERE ip_hash=?').bind(key).run();const exp=String(now+8*3600000);const sig=await mac(env.SESSION_SECRET,exp);return json({ok:true},200,{'Set-Cookie':`rk_host=${exp}.${sig}; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=28800`});
  }
  if(path==='/logout'&&method==='POST')return json({ok:true},200,{'Set-Cookie':'rk_host=; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=0'});
  if(path==='/payments'&&method==='GET'){const row=await env.DB.prepare("SELECT value FROM settings WHERE key='payments'").first();return json(row?JSON.parse(row.value):defaults)}
  if(path==='/guestbook'&&method==='GET'){const rows=await env.DB.prepare('SELECT id,name,relation,message,date FROM guestbook WHERE approved=1 ORDER BY date DESC LIMIT 100').all();return json(rows.results)}
  // Guest RSVP passcode is separate from both Host Portal passcodes.
  // Use a dedicated secret and rate-limit incorrect guest code attempts by IP.
  if(path==='/rsvp/verify'&&method==='POST' || path==='/rsvp'&&method==='POST'){
   if(!env.RSVP_GUEST_PASSCODE)return json({error:'Guest RSVP access is not configured yet.'},503);
   const ip=request.headers.get('CF-Connecting-IP')||'unknown';
   const key=await hex('guest-rsvp:'+ip+env.SESSION_SECRET);
   const now=Date.now();
   const prev=await env.DB.prepare('SELECT count,reset_at FROM login_attempts WHERE ip_hash=?').bind(key).first();
   if(prev&&prev.reset_at>now&&prev.count>=8)return json({error:'Too many attempts. Please try again in 15 minutes.'},429);
   const d=await body(request);
   const valid=safeEqual(limit(d.passcode,128),env.RSVP_GUEST_PASSCODE);
   if(!valid){
    const count=prev&&prev.reset_at>now?prev.count+1:1;
    await env.DB.prepare('INSERT INTO login_attempts (ip_hash,count,reset_at) VALUES (?,?,?) ON CONFLICT(ip_hash) DO UPDATE SET count=excluded.count,reset_at=excluded.reset_at').bind(key,count,now+900000).run();
    return json({error:'Incorrect invitation passcode. Please check the code Richard & Kim shared with you.'},403);
   }
   await env.DB.prepare('DELETE FROM login_attempts WHERE ip_hash=?').bind(key).run();
   if(path==='/rsvp/verify')return json({ok:true});
   if(d.website)return json({ok:true});
   const name=limit(d.name,120),email=limit(d.email,180),attendance=d.attendance,guests=Number(d.guests),note=limit(d.note,1000);
   if(!name||!/^\S+@\S+\.\S+$/.test(email)||!['accept','decline'].includes(attendance)||!Number.isInteger(guests)||guests<1||guests>5)return json({error:'Please check your RSVP fields'},400);
   await env.DB.prepare('INSERT INTO rsvps(id,name,email,attendance,guests,note,date) VALUES(?,?,?,?,?,?,?)').bind(crypto.randomUUID(),name,email,attendance,guests,note,new Date().toISOString()).run();
   return json({ok:true},201);
  }
  if(path==='/guestbook'&&method==='POST'){
   const d=await body(request);if(d.website)return json({ok:true});const name=limit(d.name,120),relation=limit(d.relation,120),message=limit(d.message,1000);if(!name||!message)return json({error:'Name and message are required'},400);
   await env.DB.prepare('INSERT INTO guestbook(id,name,relation,message,date,approved) VALUES(?,?,?,?,?,0)').bind(crypto.randomUUID(),name,relation,message,new Date().toISOString()).run();return json({ok:true,notice:'Submitted for host approval'},201)
  }
  if(!await authorized(request,env))return json({error:'Host login required'},401);
  if(path==='/admin/data'&&method==='GET'){const [r,g]=await Promise.all([env.DB.prepare('SELECT * FROM rsvps ORDER BY date DESC').all(),env.DB.prepare('SELECT * FROM guestbook ORDER BY date DESC').all()]);return json({rsvps:r.results,guestbook:g.results})}
  if(path==='/payments'&&method==='PUT'){
   const d=await body(request),clean={};for(const k of fields)clean[k]=limit(d[k],200);
   if(clean.richardRouting&&!/^\d{9}$/.test(clean.richardRouting))return json({error:'Routing number must be 9 digits'},400);
   if(clean.richardPaypal&&!(/^https:\/\//i.test(clean.richardPaypal)||/^\S+@\S+\.\S+$/.test(clean.richardPaypal)))return json({error:'Invalid PayPal email/link'},400);
   await env.DB.prepare("INSERT INTO settings(key,value) VALUES('payments',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(JSON.stringify(clean)).run();return json({ok:true});
  }
  if(path==='/admin/delete'&&method==='POST'){const d=await body(request);if(!['rsvps','guestbook'].includes(d.table)||typeof d.id!=='string')return json({error:'Invalid request'},400);await env.DB.prepare(`DELETE FROM ${d.table} WHERE id=?`).bind(d.id).run();return json({ok:true})}
  if(path==='/admin/approve'&&method==='POST'){const d=await body(request);if(typeof d.id!=='string')return json({error:'Invalid ID'},400);await env.DB.prepare('UPDATE guestbook SET approved=1 WHERE id=?').bind(d.id).run();return json({ok:true})}
  return json({error:'Not found'},404)
 }catch(e){console.error(e);return json({error:'Request failed; check server configuration.'},500)}
}
