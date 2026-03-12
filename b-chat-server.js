const express = require("express");
const { WebSocketServer } = require("ws");
const http = require("http");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const { v4: uuidv4 } = require("uuid");
const path = require("path");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const PORT = process.env.PORT || 8080;
const SECRET = process.env.JWT_SECRET || "bchat-secret-2026";

const db = new Database(process.env.DB_PATH || "./bchat.db");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    bio TEXT DEFAULT '',
    avatar TEXT DEFAULT '#3498db',
    online INTEGER DEFAULT 0,
    last_seen INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    type TEXT DEFAULT 'dm',
    name TEXT DEFAULT '',
    avatar TEXT DEFAULT '#3498db',
    created_by TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS conv_members (
    conv_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    joined_at INTEGER DEFAULT (strftime('%s','now')),
    PRIMARY KEY(conv_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    conv_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    sender_name TEXT NOT NULL,
    content TEXT NOT NULL,
    reply_to_id TEXT,
    reply_to_name TEXT,
    reply_to_content TEXT,
    seen_by TEXT DEFAULT '[]',
    deleted INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS blocks (
    blocker_id TEXT NOT NULL,
    blocked_id TEXT NOT NULL,
    PRIMARY KEY(blocker_id, blocked_id)
  );
  CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conv_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_mem_user ON conv_members(user_id);
`);

app.use(express.json({ limit: "5mb" }));
app.use(express.static(__dirname));

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "No token" });
  try { req.user = jwt.verify(h.split(" ")[1], SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
}

// Online tracking
const online = {};
function userOnline(uid, ws) {
  if (!online[uid]) online[uid] = new Set();
  online[uid].add(ws);
  db.prepare("UPDATE users SET online=1 WHERE id=?").run(uid);
  broadcastAll({ type: "presence", userId: uid, online: true });
}
function userOffline(uid, ws) {
  online[uid]?.delete(ws);
  if (!online[uid]?.size) {
    delete online[uid];
    const ts = Math.floor(Date.now() / 1000);
    db.prepare("UPDATE users SET online=0, last_seen=? WHERE id=?").run(ts, uid);
    broadcastAll({ type: "presence", userId: uid, online: false, last_seen: ts });
  }
}
function broadcastAll(data) {
  const s = JSON.stringify(data);
  Object.values(online).forEach(set => set.forEach(ws => ws.readyState === 1 && ws.send(s)));
}
function sendTo(uid, data) {
  const s = JSON.stringify(data);
  online[uid]?.forEach(ws => ws.readyState === 1 && ws.send(s));
}

wss.on("connection", ws => {
  ws.uid = null;
  ws.on("message", raw => {
    let d; try { d = JSON.parse(raw); } catch { return; }
    if (d.type === "auth") {
      try {
        const u = jwt.verify(d.token, SECRET);
        ws.uid = u.id;
        userOnline(u.id, ws);
        ws.send(JSON.stringify({ type: "authed", userId: u.id }));
      } catch { ws.send(JSON.stringify({ type: "error", msg: "Auth failed" })); }
      return;
    }
    if (!ws.uid) return;
    if (d.type === "typing") {
      const sender = db.prepare("SELECT name FROM users WHERE id=?").get(ws.uid);
      db.prepare("SELECT user_id FROM conv_members WHERE conv_id=? AND user_id!=?").all(d.conv_id, ws.uid)
        .forEach(m => sendTo(m.user_id, { type: "typing", conv_id: d.conv_id, name: sender?.name }));
    }
    if (d.type === "seen") {
      try {
        db.prepare("SELECT id,seen_by FROM messages WHERE conv_id=? AND sender_id!=? AND deleted=0").all(d.conv_id, ws.uid).forEach(m => {
          const seen = JSON.parse(m.seen_by || "[]");
          if (!seen.includes(ws.uid)) {
            seen.push(ws.uid);
            db.prepare("UPDATE messages SET seen_by=? WHERE id=?").run(JSON.stringify(seen), m.id);
          }
        });
        db.prepare("SELECT user_id FROM conv_members WHERE conv_id=?").all(d.conv_id)
          .forEach(m => sendTo(m.user_id, { type: "seen_update", conv_id: d.conv_id, by: ws.uid }));
      } catch {}
    }
  });
  ws.on("close", () => { if (ws.uid) userOffline(ws.uid, ws); });
  ws.on("error", () => { if (ws.uid) userOffline(ws.uid, ws); });
});

// AUTH
app.post("/api/register", async (req, res) => {
  let { name, username, password, bio } = req.body;
  if (!name || !username || !password) return res.status(400).json({ error: "All fields required" });
  username = username.toLowerCase().trim();
  if (username.length < 3) return res.status(400).json({ error: "Username min 3 characters" });
  if (password.length < 6) return res.status(400).json({ error: "Password min 6 characters" });
  if (!/^[a-z0-9_.]+$/.test(username)) return res.status(400).json({ error: "Username: letters, numbers, _ and . only" });
  if (db.prepare("SELECT id FROM users WHERE username=?").get(username)) return res.status(409).json({ error: "Username already taken" });
  const colors = ["#e94560","#3498db","#2ecc71","#9b59b6","#f39c12","#1abc9c","#e67e22","#c0392b"];
  const id = uuidv4();
  const hash = await bcrypt.hash(password, 10);
  const avatar = colors[Math.floor(Math.random() * colors.length)];
  db.prepare("INSERT INTO users (id,username,name,password,bio,avatar) VALUES (?,?,?,?,?,?)").run(id, username, name.trim(), hash, bio || "", avatar);
  const token = jwt.sign({ id, username, name: name.trim() }, SECRET, { expiresIn: "90d" });
  res.json({ token, user: { id, username, name: name.trim(), bio: bio || "", avatar } });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "All fields required" });
  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username.toLowerCase().trim());
  if (!user) return res.status(404).json({ error: "User not found" });
  if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: "Wrong password" });
  const token = jwt.sign({ id: user.id, username: user.username, name: user.name }, SECRET, { expiresIn: "90d" });
  res.json({ token, user: { id: user.id, username: user.username, name: user.name, bio: user.bio, avatar: user.avatar } });
});

app.get("/api/me", auth, (req, res) => {
  const u = db.prepare("SELECT id,username,name,bio,avatar,online,last_seen FROM users WHERE id=?").get(req.user.id);
  res.json(u);
});
app.put("/api/me", auth, (req, res) => {
  const { name, bio, avatar } = req.body;
  if (name) db.prepare("UPDATE users SET name=? WHERE id=?").run(name.trim(), req.user.id);
  if (bio !== undefined) db.prepare("UPDATE users SET bio=? WHERE id=?").run(bio, req.user.id);
  if (avatar) db.prepare("UPDATE users SET avatar=? WHERE id=?").run(avatar, req.user.id);
  res.json(db.prepare("SELECT id,username,name,bio,avatar FROM users WHERE id=?").get(req.user.id));
});

app.get("/api/users/all", auth, (req, res) => {
  res.json(db.prepare("SELECT id,username,name,bio,avatar,online,last_seen FROM users WHERE id!=? ORDER BY online DESC, name ASC").all(req.user.id));
});
app.get("/api/users/search", auth, (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.json(db.prepare("SELECT id,username,name,bio,avatar,online,last_seen FROM users WHERE id!=? ORDER BY online DESC, name ASC LIMIT 50").all(req.user.id));
  res.json(db.prepare("SELECT id,username,name,bio,avatar,online,last_seen FROM users WHERE id!=? AND (username LIKE ? OR name LIKE ?) ORDER BY online DESC LIMIT 30").all(req.user.id, `%${q}%`, `%${q}%`));
});
app.get("/api/users/by-username/:u", auth, (req, res) => {
  const user = db.prepare("SELECT id,username,name,bio,avatar,online,last_seen FROM users WHERE username=?").get(req.params.u.toLowerCase());
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json(user);
});

app.post("/api/block/:uid", auth, (req, res) => {
  try { db.prepare("INSERT OR IGNORE INTO blocks VALUES (?,?)").run(req.user.id, req.params.uid); } catch {}
  res.json({ ok: true });
});
app.delete("/api/block/:uid", auth, (req, res) => {
  db.prepare("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?").run(req.user.id, req.params.uid);
  res.json({ ok: true });
});

// CONVERSATIONS
app.get("/api/conversations", auth, (req, res) => {
  const rows = db.prepare(`
    SELECT c.id,c.type,c.name,c.avatar,c.created_at,
      (SELECT content FROM messages WHERE conv_id=c.id AND deleted=0 ORDER BY created_at DESC LIMIT 1) AS last_msg,
      (SELECT sender_name FROM messages WHERE conv_id=c.id AND deleted=0 ORDER BY created_at DESC LIMIT 1) AS last_sender,
      (SELECT created_at FROM messages WHERE conv_id=c.id ORDER BY created_at DESC LIMIT 1) AS last_at,
      (SELECT COUNT(*) FROM messages WHERE conv_id=c.id AND sender_id!=? AND deleted=0 AND seen_by NOT LIKE ?) AS unread
    FROM conversations c JOIN conv_members cm ON cm.conv_id=c.id AND cm.user_id=?
    ORDER BY COALESCE(last_at, c.created_at) DESC
  `).all(req.user.id, `%${req.user.id}%`, req.user.id);

  res.json(rows.map(c => {
    if (c.type === "dm") {
      const other = db.prepare("SELECT u.id,u.username,u.name,u.avatar,u.online,u.last_seen,u.bio FROM conv_members cm JOIN users u ON u.id=cm.user_id WHERE cm.conv_id=? AND cm.user_id!=?").get(c.id, req.user.id);
      return { ...c, other_user: other };
    }
    return { ...c, members: db.prepare("SELECT u.id,u.name,u.avatar FROM conv_members cm JOIN users u ON u.id=cm.user_id WHERE cm.conv_id=?").all(c.id) };
  }));
});

app.post("/api/conversations/dm", auth, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "userId required" });
  const target = db.prepare("SELECT id,username,name,avatar,online,last_seen,bio FROM users WHERE id=?").get(userId);
  if (!target) return res.status(404).json({ error: "User not found" });
  const existing = db.prepare("SELECT c.id FROM conversations c JOIN conv_members m1 ON m1.conv_id=c.id AND m1.user_id=? JOIN conv_members m2 ON m2.conv_id=c.id AND m2.user_id=? WHERE c.type='dm'").get(req.user.id, userId);
  if (existing) {
    const conv = db.prepare("SELECT * FROM conversations WHERE id=?").get(existing.id);
    const unread = db.prepare("SELECT COUNT(*) as c FROM messages WHERE conv_id=? AND sender_id!=? AND deleted=0 AND seen_by NOT LIKE ?").get(existing.id, req.user.id, `%${req.user.id}%`);
    return res.json({ ...conv, other_user: target, unread: unread.c });
  }
  const id = uuidv4();
  db.prepare("INSERT INTO conversations (id,type,created_by) VALUES (?,?,?)").run(id, "dm", req.user.id);
  db.prepare("INSERT INTO conv_members (conv_id,user_id,role) VALUES (?,?,?)").run(id, req.user.id, "member");
  db.prepare("INSERT INTO conv_members (conv_id,user_id,role) VALUES (?,?,?)").run(id, userId, "member");
  const conv = db.prepare("SELECT * FROM conversations WHERE id=?").get(id);
  const me = db.prepare("SELECT id,username,name,avatar FROM users WHERE id=?").get(req.user.id);
  // Notify the other user about this new conversation immediately
  sendTo(userId, { type: "new_conv", conv: { ...conv, other_user: me, unread: 0, last_msg: null } });
  res.json({ ...conv, other_user: target, unread: 0 });
});

app.post("/api/conversations/group", auth, (req, res) => {
  const { name, members } = req.body;
  if (!name || !members?.length) return res.status(400).json({ error: "Required" });
  const colors = ["#3498db","#9b59b6","#e94560","#2ecc71","#f39c12"];
  const id = uuidv4();
  const avatar = colors[Math.floor(Math.random() * colors.length)];
  db.prepare("INSERT INTO conversations (id,type,name,avatar,created_by) VALUES (?,?,?,?,?)").run(id, "group", name.trim(), avatar, req.user.id);
  db.prepare("INSERT INTO conv_members (conv_id,user_id,role) VALUES (?,?,?)").run(id, req.user.id, "admin");
  members.forEach(uid => { try { db.prepare("INSERT INTO conv_members (conv_id,user_id,role) VALUES (?,?,?)").run(id, uid, "member"); } catch {} });
  const conv = db.prepare("SELECT * FROM conversations WHERE id=?").get(id);
  const allMembers = db.prepare("SELECT u.id,u.name,u.avatar FROM conv_members cm JOIN users u ON u.id=cm.user_id WHERE cm.conv_id=?").all(id);
  members.forEach(uid => sendTo(uid, { type: "new_conv", conv: { ...conv, members: allMembers, unread: 0 } }));
  res.json({ ...conv, members: allMembers });
});

// MESSAGES
app.get("/api/messages/:convId", auth, (req, res) => {
  if (!db.prepare("SELECT conv_id FROM conv_members WHERE conv_id=? AND user_id=?").get(req.params.convId, req.user.id))
    return res.status(403).json({ error: "Not a member" });
  const msgs = db.prepare("SELECT * FROM messages WHERE conv_id=? ORDER BY created_at ASC").all(req.params.convId);
  res.json(msgs.map(m => ({ ...m, seen_by: JSON.parse(m.seen_by || "[]") })));
});

app.post("/api/messages/send", auth, (req, res) => {
  const { conv_id, content, reply_to_id, reply_to_name, reply_to_content } = req.body;
  if (!content?.trim() || !conv_id) return res.status(400).json({ error: "Missing fields" });
  if (!db.prepare("SELECT conv_id FROM conv_members WHERE conv_id=? AND user_id=?").get(conv_id, req.user.id))
    return res.status(403).json({ error: "Not a member" });
  const sender = db.prepare("SELECT id,name,username,avatar FROM users WHERE id=?").get(req.user.id);
  const id = uuidv4();
  const now = Math.floor(Date.now() / 1000);
  db.prepare("INSERT INTO messages (id,conv_id,sender_id,sender_name,content,reply_to_id,reply_to_name,reply_to_content,seen_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
    .run(id, conv_id, req.user.id, sender.name, content.trim(), reply_to_id || null, reply_to_name || null, reply_to_content || null, JSON.stringify([req.user.id]), now);
  const msgData = {
    type: "new_message", id, conv_id,
    sender_id: req.user.id, sender_name: sender.name, sender_username: sender.username, sender_avatar: sender.avatar,
    content: content.trim(),
    reply_to_id: reply_to_id || null, reply_to_name: reply_to_name || null, reply_to_content: reply_to_content || null,
    seen_by: [req.user.id], created_at: now, deleted: 0
  };
  // Real-time delivery to all other members
  db.prepare("SELECT user_id FROM conv_members WHERE conv_id=? AND user_id!=?").all(conv_id, req.user.id)
    .forEach(m => sendTo(m.user_id, msgData));
  res.json(msgData);
});

app.delete("/api/messages/:msgId", auth, (req, res) => {
  const msg = db.prepare("SELECT * FROM messages WHERE id=? AND sender_id=?").get(req.params.msgId, req.user.id);
  if (!msg) return res.status(403).json({ error: "Not your message" });
  db.prepare("UPDATE messages SET deleted=1, content='This message was deleted' WHERE id=?").run(req.params.msgId);
  db.prepare("SELECT user_id FROM conv_members WHERE conv_id=?").all(msg.conv_id)
    .forEach(m => sendTo(m.user_id, { type: "msg_deleted", id: req.params.msgId, conv_id: msg.conv_id }));
  res.json({ ok: true });
});

app.get("/api/stats", (req, res) => {
  res.json({
    users: db.prepare("SELECT COUNT(*) as c FROM users").get().c,
    messages: db.prepare("SELECT COUNT(*) as c FROM messages").get().c,
    online: Object.keys(online).length
  });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
server.listen(PORT, () => console.log(`✦ B-Chat running on port ${PORT}`));
