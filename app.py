import os, json, base64, secrets, time
from flask import Flask, request, jsonify, render_template_string
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VAULT = os.path.expanduser("~/vault.bin")
AUTOLOCK = 300  # secondi di inattività
app = Flask(__name__)
st = {"f": None, "salt": None, "data": [], "t": 0}

def derive(pw, salt):
    k = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(pw.encode())
    return Fernet(base64.urlsafe_b64encode(k))

def save():
    tok = st["f"].encrypt(json.dumps(st["data"]).encode())
    with open(VAULT + ".tmp", "wb") as fh:
        fh.write(st["salt"] + tok)
    os.replace(VAULT + ".tmp", VAULT)

def lock():
    st.update(f=None, salt=None, data=[])

def unlocked():
    if st["f"] and time.time() - st["t"] > AUTOLOCK:
        lock()
    if st["f"]:
        st["t"] = time.time()
        return True
    return False

@app.get("/")
def index():
    return render_template_string(PAGE)

@app.get("/api/status")
def status():
    return jsonify(unlocked=unlocked(), exists=os.path.exists(VAULT))

@app.post("/api/unlock")
def unlock():
    pw = (request.json or {}).get("password", "")
    if len(pw) < 8:
        return jsonify(error="Minimo 8 caratteri"), 400
    if os.path.exists(VAULT):
        raw = open(VAULT, "rb").read()
        salt, tok = raw[:16], raw[16:]
        f = derive(pw, salt)
        try:
            data = json.loads(f.decrypt(tok))
        except InvalidToken:
            time.sleep(1)
            return jsonify(error="Password errata"), 401
        st.update(f=f, salt=salt, data=data, t=time.time())
    else:
        salt = os.urandom(16)
        st.update(f=derive(pw, salt), salt=salt, data=[], t=time.time())
        save()
    return jsonify(ok=True)

@app.post("/api/lock")
def do_lock():
    lock()
    return jsonify(ok=True)

@app.get("/api/entries")
def entries():
    if not unlocked():
        return jsonify(error="Bloccato"), 401
    return jsonify(st["data"])

@app.post("/api/entries")
def add():
    if not unlocked():
        return jsonify(error="Bloccato"), 401
    d = request.json or {}
    e = {"id": secrets.token_hex(4), "site": d.get("site", "").strip(),
         "user": d.get("user", "").strip(), "pw": d.get("pw", "")}
    if not e["site"] or not e["pw"]:
        return jsonify(error="Sito e password obbligatori"), 400
    st["data"].append(e)
    save()
    return jsonify(e)

@app.delete("/api/entries/<eid>")
def delete(eid):
    if not unlocked():
        return jsonify(error="Bloccato"), 401
    st["data"] = [e for e in st["data"] if e["id"] != eid]
    save()
    return jsonify(ok=True)

@app.post("/api/change")
def change():
    if not unlocked():
        return jsonify(error="Bloccato"), 401
    d = request.json or {}
    old, new = d.get("old", ""), d.get("new", "")
    if len(new) < 8:
        return jsonify(error="Minimo 8 caratteri"), 400
    raw = open(VAULT, "rb").read()
    try:
        derive(old, raw[:16]).decrypt(raw[16:])
    except InvalidToken:
        time.sleep(1)
        return jsonify(error="Password attuale errata"), 401
    salt = os.urandom(16)
    st["f"], st["salt"] = derive(new, salt), salt
    save()
    return jsonify(ok=True)

@app.get("/manifest.webmanifest")
def manifest():
    m = {
        "name": "Password locali", "short_name": "Password",
        "start_url": "/", "scope": "/", "display": "standalone",
        "background_color": "#111111", "theme_color": "#111111",
        "icons": [
            {"src": "/static/icon-192.png", "sizes": "192x192",
             "type": "image/png", "purpose": "any maskable"},
            {"src": "/static/icon-512.png", "sizes": "512x512",
             "type": "image/png", "purpose": "any maskable"},
        ],
    }
    return app.response_class(json.dumps(m), mimetype="application/manifest+json")

@app.get("/sw.js")
def sw():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sw.js")
    r = app.response_class(open(p).read(), mimetype="application/javascript")
    r.headers["Service-Worker-Allowed"] = "/"
    return r

@app.after_request
def nostore(r):
    if request.path.startswith("/api/"):
        r.headers["Cache-Control"] = "no-store"
    return r

PAGE = """<!doctype html><html lang="it"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Password</title>
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#111111">
<style>
body{font-family:sans-serif;max-width:520px;margin:0 auto;padding:16px;background:#111;color:#eee}
input,button{font-size:16px;padding:10px;margin:4px 0;border-radius:8px;border:1px solid #444;background:#222;color:#eee;width:100%;box-sizing:border-box}
button{background:#3b82f6;border:0;cursor:pointer}button.s{background:#333;width:auto;padding:6px 10px;font-size:14px}
button.d{background:#b91c1c}.card{background:#1c1c1c;border-radius:10px;padding:12px;margin:10px 0}
.row{display:flex;gap:6px;flex-wrap:wrap;align-items:center}.row input{flex:1}.err{color:#f87171}small{color:#999}
</style></head><body>
<h2>🔐 Password</h2>
<div id="lockv"><p id="hint"></p><input id="mp" type="password" placeholder="Master password">
<button onclick="unlock()">Sblocca</button><p class="err" id="e"></p></div>
<div id="main" hidden>
<div class="row"><input id="q" placeholder="Cerca..." oninput="render()">
<button class="s" onclick="lockNow()">Blocca</button>
<button class="s" onclick="chg()">Cambia</button></div>
<div class="card"><input id="site" placeholder="Sito / app"><input id="user" placeholder="Username / email">
<div class="row"><input id="pw" placeholder="Password"><button class="s" onclick="gen()">Genera</button></div>
<button onclick="add()">Salva</button></div>
<div id="list"></div></div>
<script>
let E=[];const $=id=>document.getElementById(id);
async function api(u,m='GET',b){const r=await fetch(u,{method:m,headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined});
 const j=await r.json();if(r.status==401&&j.error=='Bloccato'){show(false)}return{ok:r.ok,j}}
function show(u){$('lockv').hidden=u;$('main').hidden=!u}
async function init(){
 try{const{j}=await api('/api/status');
  $('hint').textContent=j.exists?'Inserisci la master password':'Crea la master password (min. 8 caratteri). Se la dimentichi non si recupera!';
  if(j.unlocked){show(true);load()}else show(false)
 }catch(e){$('hint').textContent='Server non raggiungibile. Avvia python app.py in Termux.'}}
async function unlock(){const{ok,j}=await api('/api/unlock','POST',{password:$('mp').value});
 if(!ok){$('e').textContent=j.error;return}$('mp').value='';$('e').textContent='';show(true);load()}
async function load(){const{ok,j}=await api('/api/entries');if(ok){E=j;render()}}
function render(){const q=$('q').value.toLowerCase();$('list').innerHTML='';
 E.filter(e=>(e.site+e.user).toLowerCase().includes(q)).forEach(e=>{
 const d=document.createElement('div');d.className='card';
 d.innerHTML=`<b></b><br><small></small><div class=row style="margin-top:8px"></div>`;
 d.querySelector('b').textContent=e.site;d.querySelector('small').textContent=e.user;
 const r=d.querySelector('.row');
 const mk=(t,f,c)=>{const b=document.createElement('button');b.className='s '+(c||'');b.textContent=t;b.onclick=()=>f(b);r.appendChild(b)};
 mk('Copia',async b=>{await navigator.clipboard.writeText(e.pw);b.textContent='Copiata ✓';setTimeout(()=>b.textContent='Copia',1500)});
 mk('Mostra',b=>{b.textContent=b.textContent=='Mostra'?e.pw:'Mostra'});
 mk('Elimina',async()=>{if(confirm('Eliminare '+e.site+'?')){await api('/api/entries/'+e.id,'DELETE');load()}},'d');
 $('list').appendChild(d)})}
async function add(){const{ok,j}=await api('/api/entries','POST',{site:$('site').value,user:$('user').value,pw:$('pw').value});
 if(!ok){alert(j.error);return}['site','user','pw'].forEach(i=>$(i).value='');load()}
function gen(){const c='abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*?';
 const a=crypto.getRandomValues(new Uint32Array(20));$('pw').value=[...a].map(n=>c[n%c.length]).join('')}
async function lockNow(){await api('/api/lock','POST');E=[];show(false)}
async function chg(){
 const old=prompt('Password attuale:');if(!old)return;
 const nw=prompt('Nuova password (min. 8 caratteri):');if(!nw)return;
 const{ok,j}=await api('/api/change','POST',{old:old,new:nw});
 alert(ok?'Password cambiata ✓':j.error)}
if('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js');
init();
</script></body></html>"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))