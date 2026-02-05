import express from 'express'

const app = express()
app.use(express.json({ limit: '5mb' }))

let events = []

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

  // 1. GitHub App
  if (body.installation?.id) {
    return {
      type: "GitHub App",
      id: body.installation.id
    }
  }

  // 2. GitHub Actions
  if (body.sender?.login?.includes("github-actions")) {
    return {
      type: "GitHub Actions",
      id: "GITHUB_TOKEN"
    }
  }

  // 3. Deploy Key / SSH
  if (body.pusher?.name === "deploy key") {
    return {
      type: "Deploy Key / SSH",
      id: "ssh-key"
    }
  }

  // 4. OAuth Apps (VS Code / GCM)
  const agent = headers["user-agent"] || ""

  if (agent.includes("GitHub-Hookshot")) {
    return {
      type: "GitHub Web",
      id: "web-ui"
    }
  }

  if (
    agent.includes("Visual-Studio") ||
    agent.includes("vscode") ||
    agent.includes("GitCredential")
  ) {
    return {
      type: "OAuth / VS Code / Credential Manager",
      id: "oauth"
    }
  }

  // 5. Default → Personal Token or Stored Credential
  return {
    type: "Personal Token / HTTPS Credential",
    id: "pat-unknown"
  }
}

// ===== MAIN ENDPOINT =====
app.post('/git-monitor', (req, res) => {

  const body = req.body

  const repo = body.repository?.full_name
  const pusher = body.pusher?.name
  const sender = body.sender?.login
  const senderType = body.sender?.type

  const ip =
    req.headers['x-forwarded-for'] ||
    req.socket.remoteAddress

  // ===== AUTH METHOD =====
  const auth = detectAuthMethod(body, req.headers)

  // ===== COMMIT INFO =====
  let files = []
  let message = ""

  try {
    const commit = body.head_commit
    message = commit?.message || ""

    files = [
      ...(commit?.added || []),
      ...(commit?.modified || [])
    ]
  } catch {}

  // ===== BEHAVIOR DETECTION =====
  const isForce = body.forced === true
  const isAmend = /amend/i.test(message)

  const suspiciousFiles =
    files.filter(f =>
      SUSPICIOUS.some(s => f.includes(s))
    )

  const suspiciousText =
    SUSPICIOUS.filter(s =>
      message.includes(s)
    )

  // ===== RISK SCORE =====
  let risk = 0

  if (isForce) risk += 3
  if (isAmend) risk += 3
  if (suspiciousFiles.length) risk += 5
  if (suspiciousText.length) risk += 5

  // PAT + amend + malware = VERY BAD
  if (
    auth.type === "Personal Token / HTTPS Credential" &&
    (isAmend || suspiciousFiles.length)
  ) risk += 4

  const profile = {
    time: new Date().toISOString(),
    repo,
    pusher,
    sender,
    senderType,
    ip,

    authMethod: auth,

    method: {
      forcePush: isForce,
      amend: isAmend
    },

    commit: {
      message,
      files
    },

    detection: {
      suspiciousFiles,
      suspiciousText
    },

    riskScore: risk
  }

  events.unshift(profile)
  if (events.length > 200) events.pop()

  res.json({ ok: true })
})

// ===== UI =====
app.get('/', (req, res) => {

  let html = `
  <h2>Git Forensic Monitor v2.1</h2>

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
    <th>IP</th>
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

      <td>${e.ip}</td>

      <td>${e.riskScore}</td>

      <td>
        Files: ${e.detection.suspiciousFiles.join(',')}<br/>
        Text: ${e.detection.suspiciousText.join(',')}<br/>
        Amend: ${e.method.amend}
      </td>
    </tr>`
  }

  html += "</table>"
  res.send(html)
})

app.listen(3000, () =>
  console.log("Monitor v2.1 running")
)

