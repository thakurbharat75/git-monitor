import express from 'express';

const app = express();
app.use(express.json({ limit: '5mb' }));

// ===== MEMORY DB =====
const EVENTS = [];

// ===== PATTERNS =====
const BAD = [
  "temp_interactive_push.bat",
  "global['!']",
  "_$_1e42",
  "--no-verify",
  "commit --amend"
];

function analyze(payload) {
  const result = { hits: [], files: [], messages: [] };

  if (!payload.commits) return result;

  payload.commits.forEach(c => {
    const files = [...(c.added || []), ...(c.modified || [])];

    files.forEach(f =>
      BAD.forEach(p => {
        if (f.includes(p)) {
          result.hits.push(p);
          result.files.push(f);
        }
      })
    );

    if (c.message) {
      BAD.forEach(p => {
        if (c.message.includes(p)) {
          result.hits.push(p);
          result.messages.push(c.message);
        }
      });
    }
  });

  return result;
}

// ===== WEBHOOK ENDPOINT =====
app.post('/git-monitor', (req, res) => {
  const body = req.body;

  const event = {
    id: Date.now(),
    repo: body.repository?.full_name,
    branch: body.ref?.replace('refs/heads/', ''),
    pusher: body.pusher?.name,
    compare: body.compare,
    time: new Date().toISOString(),
    report: analyze(body)
  };

  EVENTS.unshift(event);
  if (EVENTS.length > 200) EVENTS.pop();

  res.send({ ok: true });
});

// ===== API FOR UI =====
app.get('/incidents', (req, res) => {
  res.json(EVENTS);
});

// ===== DASHBOARD UI =====
app.get('/', (req, res) => {
  res.send(`
  <html>
  <head>
    <title>Git Security Monitor</title>
    <style>
      body{font-family:Arial;margin:20px;background:#0e1117;color:white}
      .card{background:#161b22;padding:12px;margin:10px;border-radius:6px}
      .bad{border-left:5px solid red}
      .ok{border-left:5px solid #2ea043}
      a{color:#58a6ff}
    </style>
  </head>

  <body>
    <h2>🛡 Git Security Monitor</h2>
    <div id="app">loading...</div>

    <script>
      async function load(){
        const r = await fetch('/incidents');
        const data = await r.json();

        const html = data.map(e => {
          const bad = e.report.hits.length > 0;

          return \`
          <div class="card \${bad ? 'bad':'ok'}">
            <b>Repo:</b> \${e.repo}<br/>
            <b>Branch:</b> \${e.branch}<br/>
            <b>Pusher:</b> \${e.pusher}<br/>
            <b>Time:</b> \${e.time}<br/>

            \${bad ? '<b style="color:red">🚨 ATTACK DETECTED</b><br/>' : ''}

            <b>Files:</b> \${e.report.files.join(', ') || 'none'}<br/>
            <b>Patterns:</b> \${e.report.hits.join(', ') || 'none'}<br/>

            \${e.compare ? '<a target="_blank" href="'+e.compare+'">View Compare</a>' : ''}
          </div>
          \`;
        }).join('');

        document.getElementById('app').innerHTML = html || 'No events yet';
      }

      load();
      setInterval(load, 5000);
    </script>
  </body>
  </html>
  `);
});

app.listen(4000, () => console.log("running on 4000"));

