const $=s=>document.querySelector(s);
const api=async(m,u,b)=>{const r=await fetch(u,{method:m,headers:{'X-CSW':'1','Content-Type':'application/json'},body:b?JSON.stringify(b):undefined});const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(typeof j.detail==='string'?j.detail:'Request failed ('+r.status+')');return j};
const el=(t,x,c)=>{const e=document.createElement(t);if(x!=null)e.textContent=x;if(c)e.className=c;return e};
const lines=r=>{const o=[];
 o.push(r.tls_error?['bad','HTTPS check failed: '+r.tls_error]:r.tls_days_left!=null?[r.tls_days_left>14?'ok':'bad','TLS certificate expires in '+r.tls_days_left+' days']:['bad','No HTTPS result']);
 if(r.headers){const m=Object.keys(r.headers).filter(k=>!r.headers[k]);o.push([m.length?'bad':'ok',m.length?'Missing headers: '+m.join(', '):'All checked security headers present']);}
 if(r.http_redirects_to_https!=null)o.push([r.http_redirects_to_https?'ok':'bad',r.http_redirects_to_https?'HTTP redirects to HTTPS':'HTTP does not redirect to HTTPS']);
 o.push([r.spf?'ok':'bad',r.spf?'SPF record present':'No SPF record']);o.push([r.dmarc?'ok':'bad',r.dmarc?'DMARC record present':'No DMARC record']);
 if(r.domain_expiry_days!=null)o.push([r.domain_expiry_days>30?'ok':'bad','Domain registration expires in '+r.domain_expiry_days+' days']);
 o.push(['ok',r.subdomains.length+' subdomains seen']);r.dangling.forEach(s=>o.push(['bad','Dangling CNAME: '+s]));return o};
async function auth(k){try{await api('POST','/api/'+k,{email:$('#email').value,password:$('#pw').value});$('#pw').value='';load()}catch(e){$('#msg').textContent=e.message}}
async function act(m,u){try{await api(m,u);$('#err').textContent='';setTimeout(load,m==='POST'&&u.endsWith('/scan')?4000:0)}catch(e){$('#err').textContent=e.message}}
async function load(){let me;try{me=await api('GET','/api/me')}catch{$('#auth').hidden=false;$('#dash').hidden=true;$('#out').hidden=true;return}
 $('#auth').hidden=true;$('#dash').hidden=false;$('#out').hidden=false;$('#adminlink').hidden=!me.is_admin;$('#who').textContent=me.email+' · '+me.plan+' plan, '+me.limit+' domains';
 const box=$('#list');box.replaceChildren();const ds=await api('GET','/api/domains');if(!ds.length)box.append(el('p','Add your first domain to start weekly checks.'));
 for(const d of ds){const c=el('div',null,'card');c.append(el('h3',d.name));
  if(!d.verified){c.append(el('p','Add this DNS TXT record to prove you control the domain, then verify:'));c.append(el('pre','Name:  '+d.txt_name+'\nType:  TXT\nValue: '+d.txt_value));
   const v=el('button','Verify domain');v.onclick=()=>act('POST','/api/domains/'+d.id+'/verify');c.append(v)}
  else if(!d.scan)c.append(el('p','Verified. First scan is running; refresh in a minute.'));
  else{c.append(el('p','Last scan: '+new Date(d.scan.ts*1000).toLocaleString()));if(d.scan.changes.length){c.append(el('strong','Changes since last scan'));const u=el('ul');d.scan.changes.forEach(x=>u.append(el('li',x)));c.append(u)}
   const u=el('ul');lines(d.scan.result).forEach(([k,t])=>u.append(el('li',(k==='ok'?'Pass: ':'Check: ')+t,k)));c.append(u)}
  const row=el('div',null,'row');if(d.verified){const s=el('button','Scan now','alt');s.onclick=()=>act('POST','/api/domains/'+d.id+'/scan');row.append(s)}
  const x=el('button','Remove','alt');x.onclick=()=>confirm('Remove '+d.name+'?')&&act('DELETE','/api/domains/'+d.id);row.append(x);c.append(row);box.append(c)}}
$('#login').onclick=()=>auth('login');$('#reg').onclick=()=>auth('register');
$('#out').onclick=async()=>{await api('POST','/api/logout');load()};
$('#add').onsubmit=async e=>{e.preventDefault();try{await api('POST','/api/domains',{name:$('#dn').value});$('#dn').value='';$('#err').textContent='';load()}catch(x){$('#err').textContent=x.message}};
load();
