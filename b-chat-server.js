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
const JWT_SECRET = process.env.JWT_SECRET || "bchat-basit-2024-secret";

// ── DATABASE ──────────────────────────────────────────────────
const db = new Database(process.env.DB_PATH || "./bchat.db");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    bio TEXT DEFAULT '',
    avatar TEXT DEFAULT '',
    theme TEXT DEFAULT 'dark',
    online INTEGER DEFAULT 0,
    last_seen INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    type TEXT DEFAULT 'dm',
    name TEXT DEFAULT '',
    avatar TEXT DEFAULT '',
    created_by TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS conv_members (
    id TEXT PRIMARY KEY,
    conv_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    joined_at INTEGER DEFAULT (strftime('%s','now')),
    UNIQUE(conv_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    conv_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    sender_name TEXT NOT NULL,
    type TEXT DEFAULT 'text',
    content TEXT NOT NULL,
    reply_to_id TEXT DEFAULT NULL,
    reply_to_name TEXT DEFAULT NULL,
    reply_to_content TEXT DEFAULT NULL,
    seen_by TEXT DEFAULT '[]',
    deleted INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS blocks (
    id TEXT PRIMARY KEY,
    blocker_id TEXT NOT NULL,
    blocked_id TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    UNIQUE(blocker_id, blocked_id)
  );
`);

app.use(express.json({ limit: "10mb" }));
app.use(express.static(__dirname));

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
}

// ── ONLINE TRACKING ───────────────────────────────────────────
const onlineUsers = {}; // userId -> Set<ws>

function setOnline(userId, ws) {
  if (!onlineUsers[userId]) onlineUsers[userId] = new Set();
  onlineUsers[userId].add(ws);
  db.prepare("UPDATE users SET online=1 WHERE id=?").run(userId);
  broadcastPresence(userId, true);
}

function setOffline(userId, ws) {
  if (onlineUsers[userId]) {
    onlineUsers[userId].delete(ws);
    if (onlineUsers[userId].size === 0) {
      delete onlineUsers[userId];
      const now = Math.floor(Date.now() / 1000);
      db.prepare("UPDATE users SET online=0, last_seen=? WHERE id=?").run(now, userId);
      broadcastPresence(userId, false, now);
    }
  }
}

function broadcastPresence(userId, isOnline, lastSeen = null) {
  const msg = JSON.stringify({ type: "presence", userId, online: isOnline, last_seen: lastSeen });
  Object.values(onlineUsers).forEach(sockets => {
    sockets.forEach(ws => { if (ws.readyState === 1) ws.send(msg); });
  });
}

function sendToUser(userId, data) {
  if (!onlineUsers[userId]) return;
  const msg = JSON.stringify(data);
  onlineUsers[userId].forEach(ws => { if (ws.readyState === 1) ws.send(msg); });
}

// ── WEBSOCKET ─────────────────────────────────────────────────
wss.on("connection", (ws) => {
  ws.userId = null;

  ws.on("message", (raw) => {
    let data;
    try { data = JSON.parse(raw); } catch { return; }

    if (data.type === "auth") {
      try {
        const decoded = jwt.verify(data.token, JWT_SECRET);
        ws.userId = decoded.id;
        setOnline(decoded.id, ws);
        ws.send(JSON.stringify({ type: "authed", userId: decoded.id }));
      } catch { ws.send(JSON.stringify({ type: "error", msg: "Auth failed" })); }
    }

    else if (data.type === "send_message") {
      if (!ws.userId) return;
      const { conv_id, content, msg_type, reply_to_id, reply_to_name, reply_to_content } = data;
      if (!content || !conv_id) return;

      // Check if blocked
      const members = db.prepare("SELECT user_id FROM conv_members WHERE conv_id=?").all(conv_id);
      const conv = db.prepare("SELECT * FROM conversations WHERE id=?").get(conv_id);
      if (!conv) return;

      const sender = db.prepare("SELECT * FROM users WHERE id=?").get(ws.userId);
      if (!sender) return;

      const msgId = uuidv4();
      const now = Math.floor(Date.now() / 1000);
      const seenBy = JSON.stringify([ws.userId]);

      db.prepare(`INSERT INTO messages (id,conv_id,sender_id,sender_name,type,content,reply_to_id,reply_to_name,reply_to_content,seen_by,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
        .run(msgId, conv_id, ws.userId, sender.name, msg_type || "text", content,
          reply_to_id || null, reply_to_name || null, reply_to_content || null, seenBy, now);

      const msgData = {
        type: "new_message",
        id: msgId, conv_id, sender_id: ws.userId,
        sender_name: sender.name, sender_username: sender.username,
        sender_avatar: sender.avatar,
        msg_type: msg_type || "text", content,
        reply_to_id: reply_to_id || null,
        reply_to_name: reply_to_name || null,
        reply_to_content: reply_to_content || null,
        seen_by: [ws.userId], created_at: now
      };

      members.forEach(m => sendToUser(m.user_id, msgData));
    }

    else if (data.type === "seen") {
      if (!ws.userId) return;
      const { conv_id } = data;
      const msgs = db.prepare("SELECT id, seen_by FROM messages WHERE conv_id=? AND sender_id!=?").all(conv_id, ws.userId);
      msgs.forEach(m => {
        const seen = JSON.parse(m.seen_by || "[]");
        if (!seen.includes(ws.userId)) {
          seen.push(ws.userId);
          db.prepare("UPDATE messages SET seen_by=? WHERE id=?").run(JSON.stringify(seen), m.id);
        }
      });
      const members = db.prepare("SELECT user_id FROM conv_members WHERE conv_id=?").all(conv_id);
      members.forEach(m => sendToUser(m.user_id, { type: "seen_update", conv_id, seen_by: ws.userId }));
    }

    else if (data.type === "typing") {
      if (!ws.userId) return;
      const { conv_id } = data;
      const sender = db.prepare("SELECT name FROM users WHERE id=?").get(ws.userId);
      const members = db.prepare("SELECT user_id FROM conv_members WHERE conv_id=?").all(conv_id);
      members.forEach(m => {
        if (m.user_id !== ws.userId) sendToUser(m.user_id, { type: "typing", conv_id, userId: ws.userId, name: sender?.name });
      });
    }

    else if (data.type === "delete_message") {
      if (!ws.userId) return;
      const msg = db.prepare("SELECT * FROM messages WHERE id=? AND sender_id=?").get(data.msg_id, ws.userId);
      if (!msg) return;
      db.prepare("UPDATE messages SET deleted=1, content='This message was deleted' WHERE id=?").run(data.msg_id);
      const members = db.prepare("SELECT user_id FROM conv_members WHERE conv_id=?").all(msg.conv_id);
      members.forEach(m => sendToUser(m.user_id, { type: "message_deleted", msg_id: data.msg_id, conv_id: msg.conv_id }));
    }
  });

  ws.on("close", () => {
    if (ws.userId) setOffline(ws.userId, ws);
  });
});

// ── AUTH API ──────────────────────────────────────────────────
app.post("/api/register", async (req, res) => {
  const { name, username, password, bio } = req.body;
  if (!name || !username || !password) return res.status(400).json({ error: "All fields required" });
  if (username.length < 3) return res.status(400).json({ error: "Username min 3 chars" });
  if (password.length < 6) return res.status(400).json({ error: "Password min 6 chars" });
  if (!/^[a-z0-9_.]+$/i.test(username)) return res.status(400).json({ error: "Username: letters/numbers/._" });
  const exists = db.prepare("SELECT id FROM users WHERE username=?").get(username.toLowerCase());
  if (exists) return res.status(409).json({ error: "Username taken" });
  const hashed = await bcrypt.hash(password, 10);
  const id = uuidv4();
  // Pick random gradient avatar color
  const colors = ["#e74c3c","#3498db","#2ecc71","#9b59b6","#f39c12","#1abc9c","#e67e22","#c0392b","#16a085","#8e44ad"];
  const avatar = colors[Math.floor(Math.random() * colors.length)];
  db.prepare("INSERT INTO users (id,username,name,password,bio,avatar) VALUES (?,?,?,?,?,?)").run(id, username.toLowerCase(), name.trim(), hashed, bio || "", avatar);
  const token = jwt.sign({ id, username: username.toLowerCase(), name: name.trim() }, JWT_SECRET, { expiresIn: "90d" });
  res.json({ token, user: { id, username: username.toLowerCase(), name: name.trim(), bio: bio || "", avatar, theme: "dark" } });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "All fields required" });
  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username.toLowerCase());
  if (!user) return res.status(404).json({ error: "User not found" });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: "Wrong password" });
  const token = jwt.sign({ id: user.id, username: user.username, name: user.name }, JWT_SECRET, { expiresIn: "90d" });
  res.json({ token, user: { id: user.id, username: user.username, name: user.name, bio: user.bio, avatar: user.avatar, theme: user.theme } });
});

// ── USER API ──────────────────────────────────────────────────
app.get("/api/me", auth, (req, res) => {
  const u = db.prepare("SELECT id,username,name,bio,avatar,theme,online,last_seen FROM users WHERE id=?").get(req.user.id);
  res.json(u);
});

app.put("/api/me", auth, (req, res) => {
  const { name, bio, avatar, theme } = req.body;
  db.prepare("UPDATE users SET name=COALESCE(?,name), bio=COALESCE(?,bio), avatar=COALESCE(?,avatar), theme=COALESCE(?,theme) WHERE id=?")
    .run(name || null, bio !== undefined ? bio : null, avatar || null, theme || null, req.user.id);
  const u = db.prepare("SELECT id,username,name,bio,avatar,theme FROM users WHERE id=?").get(req.user.id);
  res.json(u);
});

app.get("/api/users/search", auth, (req, res) => {
  const q = (req.query.q || "").toLowerCase().trim();
  let users;
  if(!q || q.length <= 1) {
    users = db.prepare("SELECT id,username,name,bio,avatar,online,last_seen FROM users WHERE id!=? ORDER BY online DESC, name ASC LIMIT 50").all(req.user.id);
  } else {
    users = db.prepare("SELECT id,username,name,bio,avatar,online,last_seen FROM users WHERE (username LIKE ? OR name LIKE ?) AND id!=? ORDER BY online DESC LIMIT 20")
      .all(`%${q}%`, `%${q}%`, req.user.id);
  }
  res.json(users);
});

app.get("/api/users/:username", auth, (req, res) => {
  const u = db.prepare("SELECT id,username,name,bio,avatar,online,last_seen FROM users WHERE username=?").get(req.params.username.toLowerCase());
  if (!u) return res.status(404).json({ error: "User not found" });
  const blocked = db.prepare("SELECT id FROM blocks WHERE blocker_id=? AND blocked_id=?").get(req.user.id, u.id);
  res.json({ ...u, blocked_by_me: !!blocked });
});

// ── BLOCK API ─────────────────────────────────────────────────
app.post("/api/block/:userId", auth, (req, res) => {
  const { userId } = req.params;
  if (userId === req.user.id) return res.status(400).json({ error: "Cannot block yourself" });
  try {
    db.prepare("INSERT INTO blocks (id,blocker_id,blocked_id) VALUES (?,?,?)").run(uuidv4(), req.user.id, userId);
    res.json({ success: true });
  } catch { res.json({ success: true }); }
});

app.delete("/api/block/:userId", auth, (req, res) => {
  db.prepare("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?").run(req.user.id, req.params.userId);
  res.json({ success: true });
});

// ── CONVERSATIONS API ─────────────────────────────────────────
app.get("/api/conversations", auth, (req, res) => {
  const convs = db.prepare(`
    SELECT c.*, cm.user_id as my_user_id,
      (SELECT content FROM messages WHERE conv_id=c.id AND deleted=0 ORDER BY created_at DESC LIMIT 1) as last_msg,
      (SELECT sender_name FROM messages WHERE conv_id=c.id AND deleted=0 ORDER BY created_at DESC LIMIT 1) as last_sender,
      (SELECT created_at FROM messages WHERE conv_id=c.id ORDER BY created_at DESC LIMIT 1) as last_at,
      (SELECT COUNT(*) FROM messages WHERE conv_id=c.id AND sender_id!=? AND deleted=0
        AND json_each.value NOT IN (SELECT seen_by FROM messages WHERE conv_id=c.id AND sender_id!=?)
      ) as unread
    FROM conversations c
    JOIN conv_members cm ON cm.conv_id=c.id AND cm.user_id=?
    ORDER BY last_at DESC NULLS LAST
  `).all(req.user.id, req.user.id, req.user.id);

  // For DMs, get the other user info
  const result = convs.map(c => {
    if (c.type === "dm") {
      const other = db.prepare(`
        SELECT u.id,u.username,u.name,u.avatar,u.online,u.last_seen,u.bio
        FROM conv_members cm JOIN users u ON u.id=cm.user_id
        WHERE cm.conv_id=? AND cm.user_id!=?
      `).get(c.id, req.user.id);
      return { ...c, other_user: other };
    }
    return c;
  });

  res.json(result);
});

app.post("/api/conversations/dm", auth, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "userId required" });
  const target = db.prepare("SELECT id,username,name,avatar,online,last_seen FROM users WHERE id=?").get(userId);
  if (!target) return res.status(404).json({ error: "User not found" });

  // Check if DM already exists
  const existing = db.prepare(`
    SELECT c.id FROM conversations c
    JOIN conv_members m1 ON m1.conv_id=c.id AND m1.user_id=?
    JOIN conv_members m2 ON m2.conv_id=c.id AND m2.user_id=?
    WHERE c.type='dm'
  `).get(req.user.id, userId);

  if (existing) {
    const conv = db.prepare("SELECT * FROM conversations WHERE id=?").get(existing.id);
    return res.json({ ...conv, other_user: target });
  }

  const id = uuidv4();
  db.prepare("INSERT INTO conversations (id,type,created_by) VALUES (?,?,?)").run(id, "dm", req.user.id);
  db.prepare("INSERT INTO conv_members (id,conv_id,user_id,role) VALUES (?,?,?,?)").run(uuidv4(), id, req.user.id, "member");
  db.prepare("INSERT INTO conv_members (id,conv_id,user_id,role) VALUES (?,?,?,?)").run(uuidv4(), id, userId, "member");
  const conv = db.prepare("SELECT * FROM conversations WHERE id=?").get(id);
  res.json({ ...conv, other_user: target });
});

app.post("/api/conversations/group", auth, (req, res) => {
  const { name, members } = req.body;
  if (!name || !members?.length) return res.status(400).json({ error: "Name and members required" });
  const id = uuidv4();
  const colors = ["#3498db","#9b59b6","#e74c3c","#2ecc71","#f39c12"];
  const avatar = colors[Math.floor(Math.random() * colors.length)];
  db.prepare("INSERT INTO conversations (id,type,name,avatar,created_by) VALUES (?,?,?,?,?)").run(id, "group", name.trim(), avatar, req.user.id);
  db.prepare("INSERT INTO conv_members (id,conv_id,user_id,role) VALUES (?,?,?,?)").run(uuidv4(), id, req.user.id, "admin");
  members.forEach(uid => {
    try { db.prepare("INSERT INTO conv_members (id,conv_id,user_id,role) VALUES (?,?,?,?)").run(uuidv4(), id, uid, "member"); } catch {}
  });
  const conv = db.prepare("SELECT * FROM conversations WHERE id=?").get(id);
  const convMembers = db.prepare("SELECT u.id,u.username,u.name,u.avatar FROM conv_members cm JOIN users u ON u.id=cm.user_id WHERE cm.conv_id=?").all(id);
  res.json({ ...conv, members: convMembers });
});

// ── MESSAGES API ──────────────────────────────────────────────
app.get("/api/messages/:convId", auth, (req, res) => {
  const member = db.prepare("SELECT id FROM conv_members WHERE conv_id=? AND user_id=?").get(req.params.convId, req.user.id);
  if (!member) return res.status(403).json({ error: "Not a member" });
  const msgs = db.prepare("SELECT * FROM messages WHERE conv_id=? ORDER BY created_at ASC").all(req.params.convId);
  res.json(msgs.map(m => ({ ...m, seen_by: JSON.parse(m.seen_by || "[]") })));
});

// ── STATS ─────────────────────────────────────────────────────
app.get("/api/stats", (req, res) => {
  const users = db.prepare("SELECT COUNT(*) as c FROM users").get();
  const msgs = db.prepare("SELECT COUNT(*) as c FROM messages").get();
  const online = db.prepare("SELECT COUNT(*) as c FROM users WHERE online=1").get();
  res.json({ users: users.c, messages: msgs.c, online: online.c });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

server.listen(PORT, () => console.log(`✦ B-Chat running on http://localhost:${PORT}`));
