import express from 'express';

const app = express();
app.use(express.json({limit: '5mb'}));

const BAD = [
  "temp_interactive_push.bat",
  "global['!']",
  "_$_1e42",
  "--no-verify",
  "commit --amend"
];

function findHits(payload) {
  let hits = [];

  payload.commits?.forEach(c => {

    [...(c.added||[]), ...(c.modified||[])].forEach(f => {
      BAD.forEach(p => {
        if (f.includes(p)) hits.push(p);
      });
    });

    if (c.message) {
      BAD.forEach(p => {
        if (c.message.includes(p)) hits.push(p);
      });
    }

  });

  return [...new Set(hits)];
}

app.post('/git-monitor', (req, res) => {

  const body = req.body;

  const hits = findHits(body);

  console.log("===== EVENT =====");
  console.log("Repo  :", body.repository?.full_name);
  console.log("Pusher:", body.pusher?.name);
  console.log("Time  :", new Date().toISOString());

  if (hits.length > 0) {
    console.log("🚨 ATTACK DETECTED");
    console.log("Patterns:", hits);
  }

  res.send({ok:true});
});

app.get('/', (req,res)=>res.send("monitor running"));

app.listen(4000, ()=>console.log("running on 4000"));

