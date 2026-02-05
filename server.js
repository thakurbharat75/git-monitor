import express from 'express'
import crypto from 'crypto'

const app = express()
app.use(express.json({ limit: '5mb' }))

let events = []

// ======== PATTERNS YOU CARE ABOUT ========
const SUSPICIOUS = [
  "temp_interactive_push.bat",
  "global['!']",
  "_$_1e42",
  "--no-verify",
  "--amend"
]

// ======== MAIN WEBHOOK ========
app.post('/git-monitor', (req, res) => {

  const body = req.body

  const repo = body.repository?.full_name
  const pusher = body.pusher?.name
  const sender = body.sender?.login
  const senderType = body.sender?.type
  const installationId = body.installation?.id || "none"

  const ip =
    req.headers['x-forwarded-for'] ||
    req.socket.remoteAddress

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

  // ===== METHOD DETECTION =====
  const isForce =
    body.forced === true

  const isAmend =
    /amend/i.test(message)

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
  if (senderType === "Bot") risk += 2

  // ===== PROFILE =====
  const profile = {
    time: new Date().toISOString(),
    repo,
    pusher,
    sender,
    senderType,
    installationId,
    ip,

    method: {
      forcePush: isForce,
      amend: isAmend,
      viaApp: installationId !== "none",
      senderType
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

  console.log("==== EVENT ====")
  console.log(profile)

  res.json({ ok: true })
})

// ===== UI =====
app.get('/', (req, res) => {

  let html = `
  <h2>Git Forensic Monitor V2</h2>

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
    <th>IP</th>
    <th>Method</th>
    <th>Risk</th>
    <th>Findings</th>
  </tr>
  `

  for (const e of events) {

    const rowClass =
      e.riskScore >= 8 ? 'high' :
      e.riskScore >= 4 ? 'mid' : ''

    html += `
    <tr class="${rowClass}">
      <td>${e.time}</td>
      <td>${e.repo}</td>
      <td>${e.pusher}</td>
      <td>${e.ip}</td>

      <td>
        Force:${e.method.forcePush}<br/>
        Amend:${e.method.amend}<br/>
        App:${e.method.viaApp}<br/>
        Type:${e.method.senderType}
      </td>

      <td>${e.riskScore}</td>

      <td>
        Files:${e.detection.suspiciousFiles.join(',')}<br/>
        Text:${e.detection.suspiciousText.join(',')}
      </td>
    </tr>`
  }

  html += "</table>"
  res.send(html)
})

app.listen(3000, () =>
  console.log("Monitor v2 running")
)

