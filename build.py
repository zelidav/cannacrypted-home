"""Build cannacrypted.com - the front door.

A name, a login, and behind it the directory of everything running on the domain.

The directory is not hidden behind a JavaScript `if`. It is encrypted at build time
with AES-GCM under a key derived from the password by PBKDF2, and the page only ever
holds the ciphertext. Get the password wrong and there is nothing in the page to read -
which matters, because this list is a map of client infrastructure.

    python build.py                 # uses PASSWORD below
    python build.py "new password"  # rebuilds under a different one
"""
import base64, hashlib, json, os, secrets, sys

PASSWORD = "Cannacrypted2026!"
OUT = "index.html"
ITERATIONS = 210000

# What is actually on the domain. Grouped the way somebody looking for one of these
# would think about it, not the way DNS lists it.
DIRECTORY = [
    {"group": "Jerome Baker Designs", "items": [
        ("jbadmin", "Admin - stores, inventory, provenance, invoicing"),
        ("jbstore", "Wholesale store, per-store logins and ordering"),
        ("jbcustomer", "Customer app - verification, drops, events"),
        ("jbbudtender", "Budtender training, quiz and rewards"),
        ("signup", "Store signup and intake"),
        ("drop1", "NY Drop 1"),
        ("jbny", "Jerome Baker New York"),
        ("jbprocessor", "Processor portal"),
        ("processor", "Processor portal (alias)"),
        ("jbapp", "App entry point"),
        ("jbapps", "App entry point (alias)"),
        ("qr", "QR redirects for stickers and print"),
        ("ops", "Operations"),
        ("jbnyplan", "NY Long Island production plan - collaborative, on Railway"),
    ]},
    {"group": "Made in Xiaolin", "items": [
        ("xiaolin", "Brand hub and merch storefront"),
        ("xiaolinbudtender", "Roller Academy - training, quiz, rewards"),
        ("xiaolinpopup", "Pop-up programme one-pager"),
        ("thcxiaolin", "THC-side entry point"),
    ]},
    {"group": "Collabs and pitches", "items": [
        ("puffxjb", "PUFF x Jerome Baker - holiday collab concept"),
        ("kaleidoscope", "Kaleidoscope"),
        ("kaleidescope-collab", "Kaleidoscope collab"),
    ]},
    {"group": "Other clients", "items": [
        ("flwrgirls", "FLWR GRLS - brand ambassador staffing"),
        ("dragonfly", "Dragonfly Kitchen"),
        ("dfly", "Dragonfly Kitchen (short)"),
    ]},
    {"group": "UAT", "items": [
        ("uat-jbadmin", "Admin, staging"),
        ("uat-jbstore", "Wholesale store, staging"),
        ("uat-jbcustomer", "Customer app, staging"),
        ("uat-jbbudtender", "Budtender, staging"),
        ("uat-signup", "Signup, staging"),
        ("uat-drop1", "Drop 1, staging"),
        ("jbnyuat", "Jerome Baker New York, staging"),
    ]},
]


def encrypt(payload, password):
    """AES-256-GCM under a PBKDF2 key. Returns everything the browser needs to undo it
    except the password."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise SystemExit("pip install cryptography")
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS, 32)
    ct = AESGCM(key).encrypt(iv, json.dumps(payload).encode(), None)
    b64 = lambda b: base64.b64encode(b).decode()
    return {"salt": b64(salt), "iv": b64(iv), "ct": b64(ct), "iter": ITERATIONS}


PAGE = """<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>Cannacrypted</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<link rel="icon" href="data:image/svg+xml,%%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%%3E%%3Crect width='32' height='32' rx='8' fill='%%230B0F14'/%%3E%%3Cpath d='M10 21V11h6a5 5 0 0 1 0 10z' fill='none' stroke='%%2340E0A0' stroke-width='2.4'/%%3E%%3C/svg%%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#070A0E;--panel:#0E141B;--line:#1B2530;--ink:#E8EEF4;--dim:#7C8B99;
  --acc:#40E0A0;--acc-d:#1EA97A;--font:Inter,system-ui,-apple-system,sans-serif;
  --mono:"JetBrains Mono",ui-monospace,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);
  font-family:var(--font);-webkit-font-smoothing:antialiased;overflow-x:hidden}
/* a slow field behind everything - the only decoration on the page */
.field{position:fixed;inset:0;z-index:0;opacity:.5;
  background:
    radial-gradient(60rem 40rem at 15%% -10%%,rgba(64,224,160,.14),transparent 60%%),
    radial-gradient(50rem 40rem at 110%% 20%%,rgba(40,120,220,.13),transparent 60%%),
    radial-gradient(40rem 30rem at 50%% 120%%,rgba(64,224,160,.08),transparent 60%%)}
.grid{position:fixed;inset:0;z-index:0;opacity:.35;
  background-image:linear-gradient(var(--line) 1px,transparent 1px),
                   linear-gradient(90deg,var(--line) 1px,transparent 1px);
  background-size:64px 64px;
  -webkit-mask-image:radial-gradient(70%% 60%% at 50%% 40%%,#000,transparent);
  mask-image:radial-gradient(70%% 60%% at 50%% 40%%,#000,transparent)}
main{position:relative;z-index:1;min-height:100vh;display:flex;align-items:center;
  justify-content:center;padding:40px 22px}
.card{width:100%%;max-width:430px}
.mark{font-size:13px;letter-spacing:.42em;text-transform:uppercase;color:var(--acc);
  font-family:var(--mono);margin-bottom:14px}
h1{margin:0;font-size:clamp(38px,9vw,58px);font-weight:700;letter-spacing:-.035em;
  line-height:1}
h1 span{color:var(--acc)}
.sub{color:var(--dim);margin:14px 0 32px;font-size:15.5px;line-height:1.6}
form{display:grid;gap:11px}
label{font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim);
  font-family:var(--mono)}
input{width:100%%;background:var(--panel);border:1px solid var(--line);border-radius:11px;
  padding:14px 15px;color:var(--ink);font:inherit;font-size:15.5px;outline:none;
  transition:border-color .15s,box-shadow .15s}
input:focus{border-color:var(--acc-d);box-shadow:0 0 0 3px rgba(64,224,160,.13)}
button{margin-top:6px;background:var(--acc);color:#04120C;border:0;border-radius:11px;
  padding:15px;font:inherit;font-weight:700;font-size:15.5px;cursor:pointer;
  transition:filter .15s}
button:hover{filter:brightness(1.08)}
button:disabled{opacity:.55;cursor:default}
.err{color:#FF8080;font-size:14px;min-height:20px;margin-top:4px}
.foot{margin-top:30px;color:#4E5C69;font-size:12.5px;font-family:var(--mono);
  letter-spacing:.06em}

/* ---- the directory ---- */
.dir{display:none;position:relative;z-index:1;max-width:1000px;margin:0 auto;
  padding:56px 22px 90px}
.dir.on{display:block}
.dirhead{display:flex;align-items:flex-end;gap:16px;flex-wrap:wrap;
  border-bottom:1px solid var(--line);padding-bottom:22px;margin-bottom:34px}
.dirhead h2{margin:0;font-size:30px;font-weight:700;letter-spacing:-.02em}
.dirhead .who{margin-left:auto;color:var(--dim);font-size:13px;font-family:var(--mono)}
.grp{margin-bottom:34px}
.grp h3{margin:0 0 14px;font-size:11.5px;letter-spacing:.18em;text-transform:uppercase;
  color:var(--acc);font-family:var(--mono)}
.rows{display:grid;gap:8px}
a.row{display:flex;gap:16px;align-items:baseline;text-decoration:none;color:inherit;
  background:var(--panel);border:1px solid var(--line);border-radius:11px;
  padding:13px 16px;transition:border-color .15s,transform .15s}
a.row:hover{border-color:var(--acc-d);transform:translateX(3px)}
a.row b{font-family:var(--mono);font-weight:500;font-size:14.5px;color:var(--acc);
  white-space:nowrap}
a.row span{color:var(--dim);font-size:14.5px}
a.row i{margin-left:auto;color:#3A4753;font-style:normal;font-size:13px}
@media(max-width:620px){a.row{flex-direction:column;gap:5px}a.row i{display:none}}
</style>

<div class="field"></div><div class="grid"></div>

<main id="gate">
  <div class="card">
    <div class="mark">Cannacrypted</div>
    <h1>Canna<span>crypted</span></h1>
    <p class="sub">Everything we run, behind one door.</p>
    <form id="f" autocomplete="on">
      <div>
        <label for="e">Email</label>
        <input id="e" type="email" required autocomplete="username" placeholder="you@company.com">
      </div>
      <div>
        <label for="p">Password</label>
        <input id="p" type="password" required autocomplete="current-password" placeholder="••••••••••">
      </div>
      <button id="go" type="submit">Enter</button>
      <div class="err" id="err"></div>
    </form>
    <div class="foot">Encrypted at rest. Nothing loads until it opens.</div>
  </div>
</main>

<section class="dir" id="dir">
  <div class="dirhead">
    <h2>Directory</h2>
    <div class="who" id="who"></div>
  </div>
  <div id="body"></div>
</section>

<script>
const BLOB = %(blob)s;

const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function open_(pw){
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2",
                                             false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    {name:"PBKDF2", salt:b64(BLOB.salt), iterations:BLOB.iter, hash:"SHA-256"},
    base, {name:"AES-GCM", length:256}, false, ["decrypt"]);
  const out = await crypto.subtle.decrypt({name:"AES-GCM", iv:b64(BLOB.iv)}, key,
                                          b64(BLOB.ct));
  return JSON.parse(new TextDecoder().decode(out));
}

function render(groups, email){
  document.getElementById("who").textContent = email;
  document.getElementById("body").innerHTML = groups.map(g => `
    <div class="grp"><h3>${g.group}</h3><div class="rows">` +
    g.items.map(([h, d]) => `
      <a class="row" href="https://${h}.cannacrypted.com" target="_blank" rel="noopener">
        <b>${h}</b><span>${d}</span><i>${h}.cannacrypted.com &rarr;</i></a>`).join("") +
    `</div></div>`).join("");
  document.getElementById("gate").style.display = "none";
  document.getElementById("dir").classList.add("on");
}

document.getElementById("f").addEventListener("submit", async e => {
  e.preventDefault();
  const err = document.getElementById("err"), go = document.getElementById("go");
  err.textContent = ""; go.disabled = true; go.textContent = "Opening\\u2026";
  try {
    const groups = await open_(document.getElementById("p").value);
    render(groups, document.getElementById("e").value);
  } catch (_) {
    // a wrong password fails the GCM tag - there is nothing partial to show
    err.textContent = "That password does not open it.";
    go.disabled = false; go.textContent = "Enter";
    document.getElementById("p").select();
  }
});
</script>
</html>
"""


def build(password):
    blob = encrypt(DIRECTORY, password)
    html = PAGE % {"blob": json.dumps(blob, separators=(",", ":"))}
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(html)
    n = sum(len(g["items"]) for g in DIRECTORY)
    print("wrote %s - %d entries in %d groups, %.1f KB"
          % (OUT, n, len(DIRECTORY), len(html) / 1024.0))


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else PASSWORD)
