import express from 'express'
import pkg from 'pg'

const { Pool } = pkg

const app = express()
app.use(express.json({ limit: '5mb' }))

// ====== POSTGRES CONNECTION ======
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
})

// Create table once
await pool.query(`
CREATE TABLE IF NOT EXISTS events(
  id SERIAL PRIMARY KEY,
  data JSONB,
  created TIMESTAMP DEFAULT now()
)
`)

console.log("Postgres connected")

// ==== MALWARE PATTERNS ====
const SUSPICIOUS = [
  "temp_interactive_push.bat",
  "global['!']",
  "_$_1e42",
  "--no-verify",
  "--amend"
]

// ===== DETECT AUTH METHOD =====
function detectAuthMethod(body, headers) {

  if (body.installation?.id) {
    return { type: "GitHub App", id: body.installation.id }
  }

  if (body.sender?.login?.includes("github-actions")) {
    return { type: "GitHub Actions", id: "GITHUB_TOKEN" }
  }

  if (body.pusher?.name === "deploy key") {
    return { type: "Deploy Key / SSH", id: "ssh-key" }
  }

  const agent = headers["user-agent"] || ""

  if (agent.includes("GitHub-Hookshot")) {
    return { type: "GitHub Web", id: "web-ui" }
  }

  if (
    agent.includes("Visual-Studio") ||
    agent.includes("vscode") ||
    agent.includes("GitCredential")
  ) {
    return { type: "OAuth / VS Code / Credential Manager", id: "oauth" }
  }

  return { type: "Personal Token / HTTPS Credential", id: "pat-unknown" }
}

// ===== FORENSIC ANALYSIS =====
function analyzeCommitForensics(commit, body) {

  const findings = []

  const author =
    commit?.author?.username ||
    commit?.author?.name

  const pusher = body.pusher?.name

  if (author && pusher && author !== pusher) {
    findings.push("AUTHOR_PUSHER_MISMATCH")
  }

  const commitTime = new Date(commit?.timestamp)
  const pushTime   = new Date(body.repository?.updated_at)

  const diffMin =
    Math.abs(pushTime - commitTime) / 60000

  if (diffMin > 10) {
    findings.push("TIME_MANIPULATION")
  }

  if (body.forced === true) {
    findings.push("FORCE_PUSH")
  }

  if (/amend/i.test(commit?.message || "")) {
    findings.push("AMEND_USED")
  }

  return findings
}

// ===== MAIN ENDPOINT =====
app.post('/git-monitor', async (req, res) => {

  const body = req.body

  const repo = body.repository?.full_name
  const pusher = body.pusher?.name
  const sender = body.sender?.login
  const senderType = body.sender?.type

  const auth = detectAuthMethod(body, req.headers)

  let files = []
  let message = ""
  let forensicFindings = []

  try {
    const commit = body.head_commit

    message = commit?.message || ""

    files = [
      ...(commit?.added || []),
      ...(commit?.modified || [])
    ]

    forensicFindings =
      analyzeCommitForensics(commit, body)

  } catch {}

  const suspiciousFiles =
    files.filter(f =>
      SUSPICIOUS.some(s => f.includes(s))
    )

  const suspiciousText =
    SUSPICIOUS.filter(s =>
      message.includes(s)
    )

  let risk = 0

  if (forensicFindings.includes("FORCE_PUSH")) risk += 3
  if (forensicFindings.includes("AMEND_USED")) risk += 3
  if (forensicFindings.includes("AUTHOR_PUSHER_MISMATCH")) risk += 4
  if (forensicFindings.includes("TIME_MANIPULATION")) risk += 4

  if (suspiciousFiles.length) risk += 5
  if (suspiciousText.length) risk += 5

  if (
    auth.type === "Personal Token / HTTPS Credential" &&
    forensicFindings.length > 0
  ) risk += 4

  const profile = {
    time: new Date().toISOString(),

    repo,
    pusher,
    sender,
    senderType,

    authMethod: auth,

    commit: { message, files },

    detection: {
      suspiciousFiles,
      suspiciousText,
      forensicFindings
    },

    riskScore: risk
  }

  // ===== SAVE TO POSTGRES =====
  await pool.query(
    'INSERT INTO events(data) VALUES($1)',
    [profile]
  )

  res.json({ ok: true })
})

// ===== EXPORT ENDPOINT =====
app.get('/export', async (req, res) => {
  const r = await pool.query(
    'SELECT data FROM events ORDER BY created DESC'
  )
  res.json(r.rows.map(x => x.data))
})

// ===== UI =====
app.get('/', async (req, res) => {

  const r = await pool.query(
    'SELECT data FROM events ORDER BY created DESC LIMIT 2000'
  )

  const events = r.rows.map(x => x.data)

  let html = `
  <h2>Git Forensic Monitor v3 - POSTGRES</h2>

  <a href="/export">Download JSON</a>

  <style>
    body{font-family:Arial;margin:20px}
    .high{background:#ffcccc}
    .mid{background:#fff0b3}
    table{border-collapse:collapse;width:100%}
    td,th{border:1px solid #ccc;padding:6px}
  </style>

  <table>
  <tr>
    <th>Time</th>
    <th>Repo</th>
    <th>Pusher</th>
    <th>Auth Method</th>
    <th>Risk</th>
    <th>Findings</th>
  </tr>
  `

  for (const e of events) {

    const rowClass =
      e.riskScore >= 10 ? 'high' :
      e.riskScore >= 5 ? 'mid' : ''

    html += `
    <tr class="${rowClass}">
      <td>${e.time}</td>
      <td>${e.repo}</td>
      <td>${e.pusher}</td>

      <td>
        ${e.authMethod.type}<br/>
        id: ${e.authMethod.id}
      </td>

      <td>${e.riskScore}</td>

      <td>
        Files: ${e.detection.suspiciousFiles.join(',')}<br/>
        Text: ${e.detection.suspiciousText.join(',')}<br/>
        Forensics: ${e.detection.forensicFindings.join(',')}
      </td>
    </tr>`
  }

  html += "</table>"
  res.send(html)
})

app.listen(3000, () =>
  console.log("Monitor v3 postgres running")
)

