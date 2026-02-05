import express from 'express'
import fs from 'fs'
import path from 'path'

const app = express()
app.use(express.json({ limit: '5mb' }))

// ====== PERSISTENCE ======
const DB_FILE = path.join(process.cwd(), 'events.json')

// Load existing history
let events = []
try {
  if (fs.existsSync(DB_FILE)) {
    events = JSON.parse(fs.readFileSync(DB_FILE))
    console.log("Loaded previous events:", events.length)
  }
} catch (err) {
  console.log("No previous history found")
}

// Safe save function
function saveEvents() {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(events, null, 2))
  } catch (err) {
    console.error("Failed to save events:", err)
  }
}

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
app.post('/git-monitor', (req, res) => {

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

  // ===== SAVE PERMANENTLY =====
  events.unshift(profile)

  if (events.length > 2000)
    events.pop()

  saveEvents()

  res.json({ ok: true })
})

// ===== EXPORT ENDPOINT =====
app.get('/export', (req, res) => {
  res.json(events)
})

// ===== UI =====
app.get('/', (req, res) => {

  let html = `
  <h2>Git Forensic Monitor v3 - PERSISTENT</h2>

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
  console.log("Monitor v3 persistent running")
)

