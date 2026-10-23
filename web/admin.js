const $=s=>document.querySelector(s);
const api=async(m,u,b)=>{const r=await fetch(u,{method:m,headers:{'X-CSW':'1','Content-Type':'application/json'},body:b?JSON.stringify(b):undefined});const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(typeof j.detail==='string'?j.detail:'Request failed ('+r.status+')');return j};
const td=(x)=>{const e=document.createElement('td');if(x instanceof Node)e.append(x);else e.textContent=x;return e};
async function patch(id,b){try{await api('PATCH','/api/admin/users/'+id,b);$('#err').textContent=''}catch(e){$('#err').textContent=e.message}load()}
async function load(){try{
 const us=await api('GET','/api/admin/users'),ds=await api('GET','/api/admin/domains');
 $('#users').replaceChildren(...us.map(u=>{const tr=document.createElement('tr');
  const s=document.createElement('select');s.setAttribute('aria-label','Plan for '+u.email);['starter','agency'].forEach(p=>{const o=new Option(p,p);o.selected=u.plan===p;s.add(o)});s.onchange=()=>patch(u.id,{plan:s.value});
  const c=document.createElement('input');c.type='checkbox';c.checked=!!u.disabled;c.style.cssText='width:24px;min-height:24px';c.setAttribute('aria-label','Disable '+u.email);c.onchange=()=>patch(u.id,{disabled:c.checked});
  tr.append(td(u.email+(u.is_admin?' (admin)':'')),td(s),td(u.domains),td(u.created.slice(0,10)),td(c));return tr}));
 $('#doms').replaceChildren(...ds.map(d=>{const tr=document.createElement('tr');tr.append(td(d.name),td(d.email),td(d.verified?'Yes':'No'),td(d.last_scan?new Date(d.last_scan*1000).toLocaleString():'Never'));return tr}));
}catch(e){$('#err').textContent=e.message+' You need an admin session; sign in at /app.html.'}}
load();
