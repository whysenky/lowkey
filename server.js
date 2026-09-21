/* ============================================================================
   LOWKEY — самохостящийся мессенджер
   ----------------------------------------------------------------------------
   Один файл: сервер (Express + WebSocket) и интерфейс (HTML/CSS/JS внутри).
   Запуск:   npm install   (один раз)
             npm start     →  http://localhost:3000
   Хостинг:  Render (render.com) — см. render.yaml, развернётся автоматически.
   Данные:   хранятся в папке data/ (users.json, chats.json, messages.json)
   Файлы:    загруженные файлы лежат в папке uploads/
============================================================================ */

'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const express = require('express');
const multer = require('multer');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;

/* ============================================================================
   ХРАНИЛИЩЕ ДАННЫХ (JSON-файлы с атомарной записью)
============================================================================ */

const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

const FILES = {
  users: path.join(DATA_DIR, 'users.json'),
  chats: path.join(DATA_DIR, 'chats.json'),
  messages: path.join(DATA_DIR, 'messages.json'),
  counters: path.join(DATA_DIR, 'counters.json'),
  settings: path.join(DATA_DIR, 'settings.json'),
};

function ensureDirs() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

function loadJSON(file, fallback) {
  try {
    if (fs.existsSync(file)) {
      const raw = fs.readFileSync(file, 'utf8');
      if (raw.trim()) return JSON.parse(raw);
    }
  } catch (e) {
    console.error('Ошибка чтения', file, e.message);
  }
  return fallback;
}

function saveJSON(file, data) {
  ensureDirs();
  const tmp = file + '.tmp';
  try {
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
    try {
      fs.renameSync(tmp, file);
    } catch (e) {
      fs.rmSync(file, { force: true });
      fs.renameSync(tmp, file);
    }
  } catch (e) {
    console.error('Ошибка записи', file, e.message);
  }
}

let users = loadJSON(FILES.users, []);
let chats = loadJSON(FILES.chats, []);
let messages = loadJSON(FILES.messages, []);
let counters = loadJSON(FILES.counters, { user: 0, chat: 0, message: 0 });
let settings = loadJSON(FILES.settings, { registrationOpen: true });

function persist() {
  saveJSON(FILES.users, users);
  saveJSON(FILES.chats, chats);
  saveJSON(FILES.messages, messages);
  saveJSON(FILES.counters, counters);
  saveJSON(FILES.settings, settings);
}

function nextId(kind) {
  counters[kind] = (counters[kind] || 0) + 1;
  return counters[kind];
}

/* ============================================================================
   ПАРОЛИ И СЕССИИ
============================================================================ */

function hashPassword(p) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(p, salt, 64).toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(p, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const parts = stored.split(':');
  if (parts.length !== 2) return false;
  try {
    const test = crypto.scryptSync(p, parts[0], 64);
    const want = Buffer.from(parts[1], 'hex');
    return test.length === want.length && crypto.timingSafeEqual(test, want);
  } catch (e) {
    return false;
  }
}

// token -> userId (в памяти; после перезапуска сервера нужно войти заново)
const sessions = new Map();

function issueToken(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, userId);
  return token;
}

// Полностью выкидывает пользователя: удаляет сессии, закрывает WebSocket,
// отмечает оффлайн. Вызывается при блокировке администратором.
function kickUser(userId) {
  sessions.forEach((uid, token) => {
    if (uid === userId) sessions.delete(token);
  });
  const set = wsClients.get(userId);
  if (set) {
    set.forEach((ws) => {
      try {
        sendTo(ws, {
          type: 'error',
          code: 'blocked',
          message: 'Ваш аккаунт заблокирован администратором',
        });
        ws.close();
      } catch (e) {}
      wsUser.delete(ws);
    });
    wsClients.delete(userId);
  }
  const u = getUser(userId);
  if (u) {
    u.online = false;
    u.lastSeen = Date.now();
    persist();
    broadcastTo(peerIds(userId), { type: 'presence', user: publicUser(u) });
  }
}

/* ============================================================================
   ПУБЛИЧНЫЕ ОБЪЕКТЫ (без паролей и внутренних полей)
============================================================================ */

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    username: u.username,
    displayName: u.displayName,
    bio: u.bio || '',
    avatar: u.avatar || null,
    online: !!u.online,
    lastSeen: u.lastSeen || null,
    role: u.role || 'user',
    blocked: !!u.blocked,
    createdAt: u.createdAt,
  };
}

function getChat(id) {
  return chats.find((c) => c.id === id);
}

function getUser(id) {
  return users.find((u) => u.id === id);
}

function otherMemberId(chat, meId) {
  return (chat.members || []).find((m) => m !== meId);
}

function chatNameOf(chat, meId) {
  if (chat.type === 'private') {
    const other = getUser(otherMemberId(chat, meId));
    return other ? other.displayName || other.username : 'Удалённый пользователь';
  }
  return chat.name || 'Группа';
}

function chatAvatarOf(chat, meId) {
  if (chat.type === 'private') {
    const other = getUser(otherMemberId(chat, meId));
    return other ? other.avatar : null;
  }
  return chat.avatar || null;
}

function lastMessageOf(chatId) {
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].chatId === chatId) return messages[i];
  }
  return null;
}

function computeStatus(m) {
  if (!m) return 'sent';
  const readers = (m.readBy || []).filter((id) => id !== m.senderId);
  if (readers.length > 0) return 'read';
  if (m.delivered) return 'delivered';
  return 'sent';
}

function publicMessage(m) {
  return {
    id: m.id,
    chatId: m.chatId,
    senderId: m.senderId,
    kind: m.kind || 'text',
    text: m.text || '',
    file: m.file || null,
    voice: m.voice || null,
    deleted: !!m.deleted,
    system: !!m.system,
    createdAt: m.createdAt,
    status: computeStatus(m),
    readBy: (m.readBy || []).filter((id) => id !== m.senderId),
  };
}

function chatSummary(chat, meId) {
  const meU = getUser(meId) || {};
  const cleared = (meU.clearedChats && meU.clearedChats[chat.id]) || 0;
  let lm = lastMessageOf(chat.id);
  if (lm && cleared && lm.createdAt < cleared) lm = null;
  const unread = messages.filter(
    (m) =>
      m.chatId === chat.id &&
      m.createdAt >= cleared &&
      m.senderId !== meId &&
      !(m.readBy || []).includes(meId)
  ).length;
  let blocked = null;
  if (chat.type === 'private') {
    const otherId = otherMemberId(chat, meId);
    const me = getUser(meId);
    const other = getUser(otherId);
    if (me && other) {
      if ((me.blockedIds || []).includes(otherId)) blocked = 'me';
      else if ((other.blockedIds || []).includes(meId)) blocked = 'them';
    }
  }
  return {
    id: chat.id,
    type: chat.type,
    name: chatNameOf(chat, meId),
    avatar: chatAvatarOf(chat, meId),
    handle: chat.handle || null,
    description: chat.description || '',
    visibility: chat.visibility || 'public',
    system: !!chat.system,
    ownerId: chat.ownerId || null,
    members: (chat.members || [])
      .map((id) => publicUser(getUser(id)))
      .filter(Boolean),
    admins: chat.admins || [],
    isGroup: chat.type === 'group' || chat.type === 'channel',
    canPost: chat.type !== 'channel' || (chat.admins || []).includes(meId),
    blocked,
    createdAt: chat.createdAt,
    lastMessage: lm
      ? {
          id: lm.id,
          senderId: lm.senderId,
          text: lm.text || '',
          file: lm.file || null,
          voice: lm.voice || null,
          deleted: !!lm.deleted,
          createdAt: lm.createdAt,
        }
      : null,
    unreadCount: unread,
  };
}

/* Служебный чат с пользователем admin (уведомления о событиях) */
function adminSysChatId() {
  const admin = users.find((u) => u.username === 'admin');
  if (!admin) return null;
  let chat = chats.find(
    (c) => c.type === 'system' && c.members && c.members.includes(admin.id)
  );
  if (!chat) {
    chat = {
      id: nextId('chat'),
      type: 'system',
      system: true,
      name: '⚙ Информация',
      handle: null,
      description: 'Служебный чат: события сервера',
      visibility: 'private',
      avatar: null,
      members: [admin.id],
      admins: [admin.id],
      ownerId: admin.id,
      createdAt: Date.now(),
    };
    chats.push(chat);
  }
  return chat;
}

function pushSys(chatId, text) {
  const chat = getChat(chatId);
  if (!chat) return;
  const m = {
    id: nextId('message'),
    chatId,
    senderId: 0,
    kind: 'system',
    system: true,
    text: String(text).slice(0, 3000),
    createdAt: Date.now(),
    readBy: [],
    delivered: false,
  };
  messages.push(m);
  persist();
  broadcastTo(chat.members, { type: 'message', message: publicMessage(m) });
  (chat.members || []).forEach((id) =>
    sendToUser(id, { type: 'chat_updated', chat: chatSummary(chat, id) })
  );
}

function notifyAdmin(text) {
  const chatId = adminSysChatId();
  if (chatId) pushSys(chatId, text);
}

function peerIds(userId) {
  const myChatIds = new Set(
    chats.filter((c) => c.members && c.members.includes(userId)).map((c) => c.id)
  );
  const peers = new Set();
  chats.forEach((c) => {
    if (myChatIds.has(c.id)) {
      (c.members || []).forEach((m) => {
        if (m !== userId) peers.add(m);
      });
    }
  });
  return [...peers];
}

/* ============================================================================
   WEBSOCKET (мгновенная доставка, типизирование, статусы, присутствие)
============================================================================ */

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

// userId -> Set<ws>
const wsClients = new Map();
// ws -> userId
const wsUser = new Map();

function sendTo(ws, obj) {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}

function sendToUser(userId, obj) {
  const set = wsClients.get(userId);
  if (!set) return;
  const payload = JSON.stringify(obj);
  set.forEach((ws) => {
    if (ws.readyState === 1) ws.send(payload);
  });
}

function broadcastTo(userIds, obj) {
  const payload = JSON.stringify(obj);
  (userIds || []).forEach((id) => {
    const set = wsClients.get(id);
    if (set) {
      set.forEach((ws) => {
        if (ws.readyState === 1) ws.send(payload);
      });
    }
  });
}

server.on('upgrade', (req, socket, head) => {
  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch (e) {
    socket.destroy();
    return;
  }
  if (url.pathname === '/ws') {
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req);
    });
  } else {
    socket.destroy();
  }
});

function handleWsMessage(ws, raw) {
  let msg;
  try {
    msg = JSON.parse(raw);
  } catch (e) {
    return;
  }
  const userId = wsUser.get(ws);
  if (!userId) {
    if (msg && msg.type === 'auth') doAuth(ws, String(msg.token || ''));
    return;
  }
  switch (msg.type) {
    case 'message':
      wsCreateMessage(ws, userId, msg);
      break;
    case 'typing':
      wsTyping(ws, userId, msg);
      break;
    case 'read':
      wsRead(ws, userId, msg);
      break;
    case 'ping':
      sendTo(ws, { type: 'pong' });
      break;
    default:
      break;
  }
}

function doAuth(ws, token) {
  const userId = sessions.get(token);
  if (!userId) {
    sendTo(ws, { type: 'error', code: 'unauthorized', message: 'Сессия недействительна' });
    return;
  }
  const u = getUser(userId);
  if (!u || u.blocked) {
    sendTo(ws, {
      type: 'error',
      code: 'blocked',
      message: 'Ваш аккаунт заблокирован администратором',
    });
    ws.close();
    return;
  }
  wsUser.set(ws, userId);
  if (!wsClients.has(userId)) wsClients.set(userId, new Set());
  wsClients.get(userId).add(ws);

  if (u) {
    u.online = true;
    u.lastSeen = null;
    persist();
    broadcastTo(peerIds(userId), { type: 'presence', user: publicUser(u) });
  }

  const list = chats
    .filter((c) => c.members && c.members.includes(userId))
    .map((c) => chatSummary(c, userId));
  sendTo(ws, { type: 'init', me: publicUser(u), chats: list });
}

function wsCreateMessage(ws, senderId, msg) {
  const me = getUser(senderId);
  if (!me || me.blocked) {
    sendTo(ws, {
      type: 'error',
      code: 'blocked',
      message: 'Ваш аккаунт заблокирован администратором',
    });
    return;
  }
  const chat = getChat(Number(msg.chatId));
  if (!chat || !chat.members || !chat.members.includes(senderId)) return;

  // каналы: писать могут только администраторы
  if (chat.type === 'channel' && !(chat.admins || []).includes(senderId)) {
    sendTo(ws, {
      type: 'error',
      code: 'readonly',
      message: 'В канал могут писать только администраторы',
    });
    return;
  }
  // блокировки в личном чате (проверка на бэкенде, а не только на фронте)
  if (chat.type === 'private' && chat.members.length === 2) {
    const otherId = otherMemberId(chat, senderId);
    const other = getUser(otherId);
    if (other) {
      if ((me.blockedIds || []).includes(otherId)) {
        sendTo(ws, {
          type: 'error',
          code: 'you_blocked_user',
          message: 'Вы заблокировали этого пользователя. Чтобы писать — разблокируйте его',
        });
        return;
      }
      if ((other.blockedIds || []).includes(senderId)) {
        sendTo(ws, {
          type: 'error',
          code: 'blocked_by_user',
          message: 'Этот пользователь заблокировал вас. Сообщения не доставляются',
        });
        return;
      }
    }
  }

  const text = String(msg.text || '').trim().slice(0, 4000);
  let file = null;
  if (msg.file && typeof msg.file === 'object' && String(msg.file.url || '')) {
    file = {
      url: String(msg.file.url).slice(0, 500),
      name: String(msg.file.name || 'файл').slice(0, 255),
      size: Number(msg.file.size) || 0,
      type: String(msg.file.type || ''),
    };
  }
  let voice = null;
  if (msg.voice && typeof msg.voice === 'object' && String(msg.voice.url || '')) {
    voice = {
      url: String(msg.voice.url).slice(0, 500),
      duration: Math.round(Number(msg.voice.duration) || 0),
      wave: Array.isArray(msg.voice.wave)
        ? msg.voice.wave
            .map(Number)
            .filter((x) => typeof x === 'number' && isFinite(x) && x >= 0)
            .slice(0, 100)
        : [],
    };
  }
  if (!text && !file && !voice) return;

  const m = {
    id: nextId('message'),
    chatId: chat.id,
    senderId,
    kind: voice ? 'voice' : file ? 'file' : 'text',
    text,
    file,
    voice,
    createdAt: Date.now(),
    readBy: [senderId],
    delivered: false,
  };
  messages.push(m);

  // доставлено, если хотя бы один получатель онлайн
  const recipients = (chat.members || []).filter((id) => id !== senderId);
  m.delivered = recipients.some((id) => {
    const set = wsClients.get(id);
    return set && set.size > 0;
  });

  persist();

  const pub = publicMessage(m);
  broadcastTo(chat.members, { type: 'message', message: pub });
  // персонализированный список чатов для каждого участника
  chat.members.forEach((id) => {
    sendToUser(id, { type: 'chat_updated', chat: chatSummary(chat, id) });
  });

  // уведомление админу (юзернейм admin): кто что пишет
  if (!chat.system) {
    const who = me.displayName || me.username;
    const label =
      chat.type === 'private'
        ? 'личном чате'
        : '«' + (chat.name || '') + '»' + (chat.handle ? ' (#' + chat.handle + ')' : '');
    let what;
    if (voice) what = '[голосовое, ' + Math.round(voice.duration || 0) + 'с]';
    else if (file)
      what =
        file.type && file.type.indexOf('image') === 0
          ? '[изображение]'
          : '[файл ' + (file.name || '') + ']';
    else what = text.slice(0, 300);
    notifyAdmin('✍ ' + who + ' в ' + label + ': ' + what);
  }
}

function wsTyping(ws, userId, msg) {
  const chat = getChat(Number(msg.chatId));
  if (!chat || !chat.members || !chat.members.includes(userId)) return;
  const u = getUser(userId);
  const typing = !!msg.typing;
  (chat.members || [])
    .filter((id) => id !== userId)
    .forEach((id) =>
      sendToUser(id, {
        type: 'typing',
        chatId: chat.id,
        userId,
        name: u ? u.displayName || u.username : '',
        typing,
      })
    );
}

function wsRead(ws, userId, msg) {
  const chat = getChat(Number(msg.chatId));
  if (!chat || !chat.members || !chat.members.includes(userId)) return;
  const ids = Array.isArray(msg.messageIds)
    ? msg.messageIds.map(Number).filter(Boolean)
    : [];
  const touched = [];
  ids.forEach((id) => {
    const m = messages.find((x) => x.id === id && x.chatId === chat.id);
    if (m && m.senderId !== userId && !(m.readBy || []).includes(userId)) {
      m.readBy = m.readBy || [];
      m.readBy.push(userId);
      touched.push(m);
    }
  });
  if (touched.length) persist();
  touched.forEach((m) => {
    const pub = publicMessage(m);
    const payload = JSON.stringify({
      type: 'status',
      chatId: chat.id,
      messageId: m.id,
      status: pub.status,
      readBy: pub.readBy,
    });
    (chat.members || []).forEach((id) => {
      const set = wsClients.get(id);
      if (set) {
        set.forEach((s) => {
          if (s.readyState === 1) s.send(payload);
        });
      }
    });
  });
}

function handleWsClose(ws) {
  const userId = wsUser.get(ws);
  if (userId) {
    const set = wsClients.get(userId);
    if (set) {
      set.delete(ws);
      if (set.size === 0) {
        wsClients.delete(userId);
        const u = getUser(userId);
        if (u) {
          u.online = false;
          u.lastSeen = Date.now();
          persist();
          broadcastTo(peerIds(userId), { type: 'presence', user: publicUser(u) });
        }
      }
    }
  }
  wsUser.delete(ws);
}

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => {
    ws.isAlive = true;
  });
  ws.on('message', (data) => handleWsMessage(ws, data.toString()));
  ws.on('close', () => handleWsClose(ws));
  ws.on('error', () => {});
});

const heartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) {
      ws.terminate();
      return;
    }
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

/* ============================================================================
   EXPRESS: API + ФАЙЛЫ + ФРОНТЕНД
============================================================================ */

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

// загрузка файлов
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    ensureDirs();
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase().slice(0, 12);
    cb(null, Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 }, // 25 МБ
});

app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d' }));

// --- аутентификация ---
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const userId = token ? sessions.get(token) : undefined;
  if (!userId) {
    res.status(401).json({ error: 'Не авторизован' });
    return;
  }
  req.userId = userId;
  req.token = token;
  next();
}

app.get('/api/health', (req, res) => res.json({ ok: true }));

// --- регистрация / вход / профиль ---
app.post('/api/register', (req, res) => {
  if (!settings.registrationOpen) {
    return res.status(403).json({ error: 'Регистрация временно закрыта администратором' });
  }
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const displayName =
    String(req.body.displayName || '').trim().slice(0, 40) || username;

  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({
      error: 'Username: 3–20 символов, латиница, цифры или _',
    });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Пароль — минимум 6 символов' });
  }
  if (users.find((u) => u.username === username)) {
    return res.status(400).json({ error: 'Такой username уже занят' });
  }

  // первый зарегистрированный пользователь становится администратором
  const isFirst = users.length === 0;
  const u = {
    id: nextId('user'),
    username,
    displayName,
    bio: '',
    avatar: null,
    role: isFirst ? 'admin' : 'user',
    blocked: false,
    online: false,
    lastSeen: null,
    pass: hashPassword(password),
    createdAt: Date.now(),
  };
  users.push(u);
  persist();

  notifyAdmin(
    '👤 Новый пользователь: @"' +
      u.username +
      '" (ID ' +
      u.id +
      '), имя: ' +
      (u.displayName || '-') +
      ', дата: ' +
      new Date(u.createdAt).toLocaleString('ru-RU')
  );

  const token = issueToken(u.id);
  res.json({ token, user: publicUser(u) });
});

app.post('/api/login', (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const u = users.find((x) => x.username === username);
  if (!u || !verifyPassword(password, u.pass)) {
    return res.status(400).json({ error: 'Неверный username или пароль' });
  }
  if (u.blocked) {
    return res.status(403).json({ error: 'Ваш аккаунт заблокирован администратором' });
  }
  const token = issueToken(u.id);
  res.json({ token, user: publicUser(u) });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: publicUser(getUser(req.userId)) });
});

// список заблокированных пользователей (для профиля)
app.get('/api/me/blocked', auth, (req, res) => {
  const me = getUser(req.userId);
  if (!me) return res.status(404).json({ error: 'Пользователь не найден' });
  const list = (me.blockedIds || [])
    .map((id) => publicUser(getUser(id)))
    .filter(Boolean);
  res.json(list);
});

app.patch('/api/me', auth, (req, res) => {
  const u = getUser(req.userId);
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  const oldName = u.username;
  if (typeof req.body.username === 'string') {
    const nu = String(req.body.username).trim().toLowerCase();
    if (nu !== u.username) {
      if (!/^[a-z0-9_]{3,20}$/.test(nu)) {
        return res.status(400).json({ error: 'Username: 3–20 символов, латиница, цифры или _' });
      }
      if (users.find((x) => x.username === nu)) {
        return res.status(400).json({ error: 'Такой username уже занят' });
      }
      u.username = nu;
    }
  }
  if (typeof req.body.displayName === 'string') {
    u.displayName = req.body.displayName.trim().slice(0, 40) || u.username;
  }
  if (typeof req.body.bio === 'string') {
    u.bio = req.body.bio.trim().slice(0, 200);
  }
  persist();
  broadcastTo(peerIds(u.id), { type: 'profile_updated', user: publicUser(u) });
  // обновить списки участников во всех общих чатах
  chats.forEach((c) => {
    if (c.members && c.members.includes(u.id)) {
      (c.members || []).forEach((id) =>
        sendToUser(id, { type: 'chat_updated', chat: chatSummary(c, id) })
      );
    }
  });
  if (oldName !== u.username) {
    notifyAdmin('✏️ @' + oldName + ' сменил username на @' + u.username);
  }
  res.json({ user: publicUser(u) });
});

app.post('/api/me/avatar', auth, upload.single('file'), (req, res) => {
  const u = getUser(req.userId);
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  if (req.body && req.body.clear) {
    u.avatar = null;
  } else if (req.file) {
    u.avatar = '/uploads/' + req.file.filename;
  } else {
    return res.status(400).json({ error: 'Нет файла' });
  }
  persist();
  broadcastTo(peerIds(u.id), { type: 'profile_updated', user: publicUser(u) });
  chats.forEach((c) => {
    if (c.members && c.members.includes(u.id)) {
      (c.members || []).forEach((id) =>
        sendToUser(id, { type: 'chat_updated', chat: chatSummary(c, id) })
      );
    }
  });
  res.json({ user: publicUser(u) });
});

app.post('/api/logout', auth, (req, res) => {
  sessions.delete(req.token);
  res.json({ ok: true });
});

/* --- админ-панель: только для администраторов --- */
function adminOnly(req, res, next) {
  const u = getUser(req.userId);
  if (!u || u.role !== 'admin') {
    return res.status(403).json({ error: 'Нет прав администратора' });
  }
  if (u.blocked) {
    return res.status(403).json({ error: 'Ваш аккаунт заблокирован администратором' });
  }
  next();
}

app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const q = String(req.query.q || '').toLowerCase().trim();
  const perPage = Math.min(Math.max(Number(req.query.perPage) || 50, 5), 100);
  const page = Math.max(Number(req.query.page) || 1, 1);
  const sort = String(req.query.sort || 'newest');
  let list = users.slice();
  if (q) {
    list = list.filter((u) => {
      if (/^\d+$/.test(q) && String(u.id) === q) return true;
      return (
        u.username.indexOf(q) >= 0 ||
        (u.displayName || '').toLowerCase().indexOf(q) >= 0 ||
        String(u.id).indexOf(q) >= 0
      );
    });
  }
  if (sort === 'oldest') list.sort((a, b) => a.id - b.id);
  else if (sort === 'id') list.sort((a, b) => b.id - a.id);
  else if (sort === 'name') list.sort((a, b) => a.username.localeCompare(b.username));
  else list.sort((a, b) => b.id - a.id); // newest
  const total = list.length;
  const pages = Math.max(1, Math.ceil(total / perPage));
  const safePage = Math.min(page, pages);
  const pageUsers = list
    .slice((safePage - 1) * perPage, safePage * perPage)
    .map(publicUser);
  res.json({ users: pageUsers, total, page: safePage, perPage, pages });
});

app.get('/api/admin/stats', auth, adminOnly, (req, res) => {
  res.json({
    users: users.length,
    chats: chats.length,
    messages: messages.length,
  });
});

app.get('/api/admin/settings', auth, adminOnly, (req, res) => {
  res.json(settings);
});

app.post('/api/admin/settings', auth, adminOnly, (req, res) => {
  if (typeof req.body.registrationOpen === 'boolean') {
    settings.registrationOpen = req.body.registrationOpen;
  }
  persist();
  res.json(settings);
});

app.post('/api/admin/users/:id/block', auth, adminOnly, (req, res) => {
  const target = getUser(Number(req.params.id));
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  if (target.id === req.userId) {
    return res.status(400).json({ error: 'Нельзя заблокировать самого себя' });
  }
  if (target.role === 'admin') {
    return res.status(400).json({ error: 'Нельзя блокировать администратора' });
  }
  const blocked = !!req.body.blocked;
  target.blocked = blocked;
  persist();
  if (blocked) kickUser(target.id);
  broadcastTo(peerIds(target.id), { type: 'profile_updated', user: publicUser(target) });
  res.json({ user: publicUser(target) });
});

app.post('/api/admin/users/:id/role', auth, adminOnly, (req, res) => {
  const target = getUser(Number(req.params.id));
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  if (target.id === req.userId) {
    return res.status(400).json({ error: 'Нельзя менять свою роль в панели' });
  }
  const role = req.body.role === 'admin' ? 'admin' : 'user';
  target.role = role;
  persist();
  broadcastTo(peerIds(target.id), { type: 'profile_updated', user: publicUser(target) });
  res.json({ user: publicUser(target) });
});

// --- поиск и профили ---
app.get('/api/users/search', auth, (req, res) => {
  const q = String(req.query.q || '').toLowerCase().trim();
  if (!q) return res.json([]);
  const result = users
    .filter(
      (u) =>
        u.id !== req.userId &&
        !u.blocked &&
        (u.username.includes(q) ||
          (u.displayName || '').toLowerCase().includes(q) ||
          String(u.id).includes(q))
    )
    .slice(0, 20)
    .map(publicUser);
  res.json(result);
});

// карточка пользователя (публичная) + статусы блокировок
app.get('/api/users/:id', auth, (req, res) => {
  const u = getUser(Number(req.params.id));
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  const me = getUser(req.userId);
  const p = publicUser(u);
  p.youBlocked = !!(me && (me.blockedIds || []).includes(u.id));
  p.blockedYou = !!((u.blockedIds || []).includes(req.userId));
  res.json({ user: p });
});

// точный поиск для ссылок-профилей (?user=)
app.get('/api/users/find', auth, (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase().replace(/^@/, '');
  let u = null;
  if (/^\d+$/.test(q)) u = users.find((x) => String(x.id) === q);
  if (!u) u = users.find((x) => x.username === q);
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  const p = publicUser(u);
  p.youBlocked = !!((getUser(req.userId) || {}).blockedIds || []).includes(u.id);
  p.blockedYou = !!((u.blockedIds || []).includes(req.userId));
  res.json({ user: p });
});

// блокировка/разблокировка пользователя (может любой пользователь)
app.post('/api/users/:id/block', auth, (req, res) => {
  const me = getUser(req.userId);
  if (!me) return res.status(404).json({ error: 'Пользователь не найден' });
  const target = getUser(Number(req.params.id));
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  if (target.id === me.id) {
    return res.status(400).json({ error: 'Нельзя заблокировать самого себя' });
  }
  me.blockedIds = me.blockedIds || [];
  const blocked = !!req.body.blocked;
  const i = me.blockedIds.indexOf(target.id);
  if (blocked && i < 0) me.blockedIds.push(target.id);
  if (!blocked && i >= 0) me.blockedIds.splice(i, 1);
  persist();
  const dm = chats.find(
    (c) =>
      c.type === 'private' &&
      c.members &&
      c.members.includes(me.id) &&
      c.members.includes(target.id) &&
      c.members.length === 2
  );
  if (dm) {
    [me.id, target.id].forEach((id) =>
      sendToUser(id, { type: 'chat_updated', chat: chatSummary(dm, id) })
    );
  }
  sendToUser(target.id, { type: 'blocks_updated', userId: me.id, blocked });
  notifyAdmin(
    '🚫 @' +
      me.username +
      (blocked ? ' заблокировал(а) ' : ' разблокировал(а) ') +
      '@' +
      target.username
  );
  res.json({ ok: true, blocked });
});

// --- чаты ---
app.get('/api/chats', auth, (req, res) => {
  const list = chats
    .filter((c) => c.members && c.members.includes(req.userId))
    .map((c) => chatSummary(c, req.userId));
  list.sort((a, b) => {
    const ta = a.lastMessage ? a.lastMessage.createdAt : a.createdAt;
    const tb = b.lastMessage ? b.lastMessage.createdAt : b.createdAt;
    return tb - ta;
  });
  res.json(list);
});

app.get('/api/chats/:id', auth, (req, res) => {
  const chat = getChat(Number(req.params.id));
  if (!chat || !chat.members || !chat.members.includes(req.userId)) {
    return res.status(403).json({ error: 'Нет доступа' });
  }
  res.json(chatSummary(chat, req.userId));
});

app.post('/api/chats/private', auth, (req, res) => {
  const otherId = Number(req.body.userId);
  if (!otherId || otherId === req.userId) {
    return res.status(400).json({ error: 'Нельзя создать чат с собой' });
  }
  const other = getUser(otherId);
  if (!other) return res.status(404).json({ error: 'Пользователь не найден' });
  if (other.blocked) {
    return res.status(403).json({ error: 'Этот пользователь заблокирован' });
  }

  const existing = chats.find(
    (c) =>
      c.type === 'private' &&
      c.members &&
      c.members.includes(req.userId) &&
      c.members.includes(otherId) &&
      c.members.length === 2
  );
  if (existing) return res.json(chatSummary(existing, req.userId));

  const chat = {
    id: nextId('chat'),
    type: 'private',
    name: null,
    avatar: null,
    members: [req.userId, otherId],
    admins: [],
    createdAt: Date.now(),
  };
  chats.push(chat);
  persist();
  sendToUser(otherId, { type: 'chat_updated', chat: chatSummary(chat, otherId) });
  res.json(chatSummary(chat, req.userId));
});

app.post('/api/chats/group', auth, (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  if (!name) return res.status(400).json({ error: 'Название группы обязательно' });
  const memberIds = [
    req.userId,
    ...(Array.isArray(req.body.memberIds)
      ? req.body.memberIds
          .map(Number)
          .filter((id) => id && id !== req.userId && getUser(id))
      : []),
  ].slice(0, 100);
  if (memberIds.length < 2) {
    return res.status(400).json({ error: 'Добавьте хотя бы одного участника' });
  }
  const chat = {
    id: nextId('chat'),
    type: 'group',
    name,
    avatar: null,
    members: memberIds,
    admins: [req.userId],
    createdAt: Date.now(),
  };
  chats.push(chat);
  persist();
  memberIds.forEach((id) =>
    sendToUser(id, { type: 'chat_updated', chat: chatSummary(chat, id) })
  );
  res.json(chatSummary(chat, req.userId));
});

// --- каналы ---
const MAX_CHANNELS = 5;
app.post('/api/channels', auth, (req, res) => {
  const me = getUser(req.userId);
  if (!me) return res.status(404).json({ error: 'Пользователь не найден' });
  const name = String(req.body.name || '').trim().slice(0, 60);
  if (!name) return res.status(400).json({ error: 'Название канала обязательно' });
  const handle = String(req.body.handle || '')
    .trim()
    .toLowerCase()
    .replace(/^@/, '');
  if (!/^[a-z0-9_]{3,24}$/.test(handle)) {
    return res.status(400).json({
      error: '@handle: 3–24 символа, латиница, цифры или _ (без пробелов)',
    });
  }
  if (chats.some((c) => c.type === 'channel' && c.handle === handle)) {
    return res.status(400).json({ error: 'Такой @handle уже занят другим каналом' });
  }
  const myCount = chats.filter(
    (c) => c.type === 'channel' && (c.admins || []).includes(me.id)
  ).length;
  if (myCount >= MAX_CHANNELS) {
    return res.status(400).json({ error: 'Лимит: не больше ' + MAX_CHANNELS + ' каналов на пользователя' });
  }
  const admins = [
    me.id,
    ...(Array.isArray(req.body.admins)
      ? req.body.admins
          .map(Number)
          .filter((id) => id && id !== me.id && getUser(id))
      : []),
  ].slice(0, 20);
  // заблокированных (в обе стороны) не добавляем
  const clean = admins.filter((id) => {
    const t = getUser(id);
    return (
      !(me.blockedIds || []).includes(id) && !((t.blockedIds || []).includes(me.id))
    );
  });
  const members = [...new Set([me.id, ...clean])];
  const chat = {
    id: nextId('chat'),
    type: 'channel',
    name,
    handle,
    description: String(req.body.description || '').slice(0, 300),
    avatar: null,
    visibility: req.body.visibility === 'private' ? 'private' : 'public',
    members,
    admins: [me.id, ...clean],
    ownerId: me.id,
    createdAt: Date.now(),
  };
  chats.push(chat);
  persist();
  members.forEach((id) => sendToUser(id, { type: 'chat_updated', chat: chatSummary(chat, id) }));
  notifyAdmin('📢 @' + me.username + ' создал канал «' + name + '» (#' + handle + ')');
  res.json(chatSummary(chat, me.id));
});

// поиск канала по @handle (для ссылки-приглашения)
app.get('/api/chats/by-handle', auth, (req, res) => {
  const h = String(req.query.h || '').trim().toLowerCase().replace(/^@/, '');
  const chat = chats.find((c) => c.type === 'channel' && c.handle === h);
  if (!chat) return res.status(404).json({ error: 'Канал не найден' });
  if (chat.visibility === 'private' && !(chat.members || []).includes(req.userId)) {
    return res.status(403).json({ error: 'Это приватный канал — доступ только по приглашению' });
  }
  res.json(chatSummary(chat, req.userId));
});

// подписка на канал
app.post('/api/chats/:id/join', auth, (req, res) => {
  const chat = getChat(Number(req.params.id));
  if (!chat || chat.type !== 'channel') {
    return res.status(404).json({ error: 'Канал не найден' });
  }
  if (chat.visibility === 'private' && !(chat.members || []).includes(req.userId)) {
    return res.status(403).json({
      error: 'Приватный канал: доступ только по приглашению администратора',
    });
  }
  if ((chat.members || []).includes(req.userId)) {
    return res.json(chatSummary(chat, req.userId));
  }
  chat.members.push(req.userId);
  persist();
  (chat.members || []).forEach((id) =>
    sendToUser(id, { type: 'chat_updated', chat: chatSummary(chat, id) })
  );
  notifyAdmin('👋 @' + (getUser(req.userId) || {}).username + ' подписался на канал #' + chat.handle);
  res.json(chatSummary(chat, req.userId));
});

// выход из группы/канала
app.post('/api/chats/:id/leave', auth, (req, res) => {
  const chat = getChat(Number(req.params.id));
  if (!chat) return res.status(404).json({ error: 'Чат не найден' });
  if (!(chat.members || []).includes(req.userId)) {
    return res.status(400).json({ error: 'Вы не участник этого чата' });
  }
  if (chat.type === 'private') {
    return res.status(400).json({ error: 'Личный чат нельзя покинуть — используйте «Очистить историю»' });
  }
  chat.members = (chat.members || []).filter((id) => id !== req.userId);
  if (chat.type === 'channel') {
    chat.admins = (chat.admins || []).filter((id) => id !== req.userId);
  }
  persist();
  (chat.members || []).forEach((id) =>
    sendToUser(id, { type: 'chat_updated', chat: chatSummary(chat, id) })
  );
  res.json({ ok: true });
});

// добавление участников администратором (группы и каналы)
app.post('/api/chats/:id/members', auth, (req, res) => {
  const chat = getChat(Number(req.params.id));
  if (!chat) return res.status(404).json({ error: 'Чат не найден' });
  if (!(chat.members || []).includes(req.userId)) {
    return res.status(403).json({ error: 'Нет доступа' });
  }
  if (!(chat.admins || []).includes(req.userId)) {
    return res.status(403).json({ error: 'Добавлять участников может только администратор' });
  }
  const me = getUser(req.userId);
  const ids = (Array.isArray(req.body.userIds) ? req.body.userIds : [])
    .map(Number)
    .filter((id) => id && id !== req.userId && getUser(id));
  const clean = ids.filter((id) => {
    const t = getUser(id);
    return (
      !(me.blockedIds || []).includes(id) && !((t.blockedIds || []).includes(me.id))
    );
  });
  let changed = 0;
  clean.forEach((id) => {
    if (!(chat.members || []).includes(id)) {
      chat.members.push(id);
      changed++;
    }
  });
  persist();
  if (changed) {
    (chat.members || []).forEach((id) =>
      sendToUser(id, { type: 'chat_updated', chat: chatSummary(chat, id) })
    );
  }
  res.json(chatSummary(chat, req.userId));
});

// --- сообщения ---
app.get('/api/chats/:id/messages', auth, (req, res) => {
  const id = Number(req.params.id);
  const chat = getChat(id);
  if (!chat || !chat.members || !chat.members.includes(req.userId)) {
    return res.status(403).json({ error: 'Нет доступа' });
  }
  let limit = Math.min(Number(req.query.limit) || 30, 100);
  const before = Number(req.query.before) || 0;
  const meU = getUser(req.userId) || {};
  const cleared = (meU.clearedChats && meU.clearedChats[id]) || 0;
  const list = messages
    .filter(
      (m) =>
        m.chatId === id && m.createdAt >= cleared && (!before || m.id < before)
    )
    .sort((a, b) => b.id - a.id)
    .slice(0, limit)
    .reverse()
    .map(publicMessage);
  res.json(list);
});

// удаление сообщения (своё; админ может любое)
app.delete('/api/chats/:id/messages/:mid', auth, (req, res) => {
  const chat = getChat(Number(req.params.id));
  if (!chat || !(chat.members || []).includes(req.userId)) {
    return res.status(403).json({ error: 'Нет доступа' });
  }
  const m = messages.find(
    (x) => x.id === Number(req.params.mid) && x.chatId === chat.id
  );
  if (!m) return res.status(404).json({ error: 'Сообщение не найдено' });
  const me = getUser(req.userId);
  const isAdmin = me && me.role === 'admin';
  if (m.senderId !== req.userId && !isAdmin) {
    return res.status(403).json({ error: 'Можно удалять только свои сообщения' });
  }
  if (m.deleted) return res.json({ ok: true });
  m.deleted = true;
  persist();
  broadcastTo(chat.members, {
    type: 'message_deleted',
    chatId: chat.id,
    messageId: m.id,
  });
  res.json({ ok: true });
});

// очистка истории (только у себя)
app.delete('/api/chats/:id/messages', auth, (req, res) => {
  const chat = getChat(Number(req.params.id));
  if (!chat || !(chat.members || []).includes(req.userId)) {
    return res.status(403).json({ error: 'Нет доступа' });
  }
  const me = getUser(req.userId);
  me.clearedChats = me.clearedChats || {};
  me.clearedChats[chat.id] = Date.now();
  persist();
  sendToUser(req.userId, { type: 'chat_updated', chat: chatSummary(chat, req.userId) });
  res.json({ ok: true });
});

// --- загрузка файлов для сообщений ---
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Нет файла' });
  res.json({
    url: '/uploads/' + req.file.filename,
    name: req.file.originalname,
    size: req.file.size,
    type: req.file.mimetype,
  });
});

ensureDirs();

/* ============================================================================
   ФРОНТЕНД (интерфейс Lowkey)
============================================================================ */

const INDEX_HTML = `<!doctype html>
<html lang="ru" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0f1117">
<title>Lowkey</title>
<link rel="icon" href="data:,">
<style>
:root{
  --accent:#7c6cff; --accent2:#5b8cff; --ok:#22c55e; --danger:#ef4444;
}
[data-theme="dark"]{
  --bg:#0f1117; --bg2:#141722; --side:#11141d; --surf:#1a1e2b; --surf2:#222738;
  --text:#e8eaf2; --muted:#8b92a5; --border:#232940; --shadow:rgba(0,0,0,.45);
  --own-grad:linear-gradient(135deg,#6d5df0,#4e7bff);
  --msg-hover:#202537;
}
[data-theme="light"]{
  --bg:#eef0f6; --bg2:#e6e9f2; --side:#ffffff; --surf:#ffffff; --surf2:#f2f4fa;
  --text:#191c27; --muted:#6b7280; --border:#e0e3ee; --shadow:rgba(20,25,60,.12);
  --own-grad:linear-gradient(135deg,#6d5df0,#4e7bff);
  --msg-hover:#f0f2fa;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  background:var(--bg); color:var(--text); overflow:hidden;
}
button{font:inherit;color:inherit;background:none;border:none;cursor:pointer}
input,textarea{font:inherit;color:inherit}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:8px}
::-webkit-scrollbar-track{background:transparent}

/* ---------- экран входа ---------- */
#view-auth{
  position:fixed;inset:0;display:flex;align-items:center;justify-content:center;
  background:
    radial-gradient(900px 500px at 80% -10%, rgba(124,108,255,.18), transparent 60%),
    radial-gradient(700px 500px at 10% 110%, rgba(91,140,255,.14), transparent 60%),
    var(--bg);
}
.auth-card{
  width:min(400px,92vw); background:var(--surf); border:1px solid var(--border);
  border-radius:20px; padding:32px 28px; box-shadow:0 24px 60px var(--shadow);
}
.auth-logo{
  display:flex;align-items:center;gap:10px;font-size:26px;font-weight:800;margin-bottom:6px;
}
.auth-logo .dot{width:14px;height:14px;border-radius:4px;background:var(--own-grad);box-shadow:0 0 18px rgba(124,108,255,.8)}
.auth-sub{color:var(--muted);font-size:14px;margin-bottom:24px}
.tabs{display:flex;background:var(--bg2);border-radius:12px;padding:4px;margin-bottom:20px;gap:4px}
.tabs button{flex:1;padding:9px 0;border-radius:9px;color:var(--muted);font-weight:600;font-size:14px}
.tabs button.on{background:var(--surf);color:var(--text);box-shadow:0 2px 8px var(--shadow)}
.field{margin-bottom:14px}
.field label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px;font-weight:600}
.field input{
  width:100%;padding:11px 14px;background:var(--bg2);border:1px solid var(--border);
  border-radius:10px;font-size:15px;outline:none;transition:border .15s;
}
.field input:focus{border-color:var(--accent)}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:11px 18px;border-radius:10px;font-weight:700;font-size:15px;
  transition:filter .15s,transform .05s;
}
.btn:active{transform:scale(.98)}
.btn-primary{background:var(--own-grad);color:#fff;width:100%}
.btn-primary:hover{filter:brightness(1.08)}
.btn-ghost{background:var(--surf2);border:1px solid var(--border)}
.btn-ghost:hover{filter:brightness(1.05)}
.btn-danger{background:rgba(239,68,68,.15);color:var(--danger)}
.err{display:none;background:rgba(239,68,68,.12);color:#f87171;border:1px solid rgba(239,68,68,.3);
  padding:10px 12px;border-radius:10px;font-size:13px;margin-bottom:14px}
.err.show{display:block}

/* ---------- приложение ---------- */
#view-app{position:fixed;inset:0;display:none}
#view-app.show{display:flex}
.sidebar{
  width:400px;min-width:320px;background:var(--side);border-right:1px solid var(--border);
  display:flex;flex-direction:column;height:100%;
}
.sb-top{display:flex;align-items:center;gap:10px;padding:14px 16px 10px}
.sb-logo{display:flex;align-items:center;gap:8px;font-weight:800;font-size:19px;flex:1}
.sb-logo .dot{width:12px;height:12px;border-radius:4px;background:var(--own-grad)}
.icon-btn{
  width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;
  color:var(--muted);font-size:18px;transition:background .15s,color .15s;
}
.icon-btn:hover{background:var(--surf2);color:var(--text)}
.search-wrap{position:relative;padding:6px 16px 8px}
.search-wrap input{
  width:100%;padding:10px 14px 10px 38px;background:var(--surf);border:1px solid var(--border);
  border-radius:12px;font-size:14px;outline:none;
}
.search-wrap input:focus{border-color:var(--accent)}
.search-wrap .ico{position:absolute;left:28px;top:17px;color:var(--muted);font-size:14px;pointer-events:none}
.search-res{
  position:absolute;left:16px;right:16px;top:52px;z-index:60;background:var(--surf);
  border:1px solid var(--border);border-radius:12px;box-shadow:0 18px 44px var(--shadow);
  overflow:hidden;display:none;
}
.search-res.show{display:block}
.sr-item{display:flex;align-items:center;gap:12px;padding:10px 14px;cursor:pointer;width:100%;text-align:left}
.sr-item:hover{background:var(--surf2)}
.sr-meta{flex:1;min-width:0}
.sr-name{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sr-un{color:var(--muted);font-size:12px}
.sr-null{padding:12px 14px;color:var(--muted);font-size:13px}

.chat-list{flex:1;overflow-y:auto;padding:4px 8px 12px}
.cl-item{
  display:flex;align-items:center;gap:12px;padding:11px 10px;border-radius:14px;cursor:pointer;
  transition:background .12s;position:relative;
}
.cl-item:hover{background:var(--surf)}
.cl-item.active{background:var(--surf2)}
.avatar{
  width:48px;height:48px;border-radius:50%;flex:none;display:flex;align-items:center;justify-content:center;
  color:#fff;font-weight:700;font-size:17px;overflow:hidden;position:relative;user-select:none;
}
.avatar img{width:100%;height:100%;object-fit:cover}
.avatar.small{width:34px;height:34px;font-size:13px}
.avatar.xs{width:26px;height:26px;font-size:11px}
.online-dot{
  position:absolute;bottom:0;right:0;width:13px;height:13px;border-radius:50%;
  background:var(--ok);border:2px solid var(--side);
}
.cl-main{flex:1;min-width:0}
.cl-top{display:flex;align-items:center;gap:8px}
.cl-name{font-weight:600;font-size:15px;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cl-time{font-size:11px;color:var(--muted);flex:none}
.cl-bot{display:flex;align-items:center;gap:6px;margin-top:3px}
.cl-prev{flex:1;color:var(--muted);font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cl-prev .me{color:var(--muted)}
.badge{
  min-width:20px;height:20px;border-radius:10px;background:var(--accent);color:#fff;
  font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center;padding:0 6px;
}
.chat-panel{flex:1;display:flex;flex-direction:column;background:var(--bg);min-width:0}
.chat-head{
  display:flex;align-items:center;gap:12px;padding:12px 18px;background:var(--bg2);
  border-bottom:1px solid var(--border);
}
.ch-back{display:none}
.ch-title{flex:1;min-width:0}
.ch-name{font-weight:700;font-size:16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ch-status{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ch-status.online{color:var(--ok);font-weight:600}
.ch-actions{display:flex;gap:4px}

.msgs{flex:1;overflow-y:auto;padding:16px 20px 8px;scroll-behavior:smooth}
.msgs-inner{max-width:820px;margin:0 auto;display:flex;flex-direction:column;gap:2px}
.day-sep{text-align:center;color:var(--muted);font-size:12px;margin:10px 0 6px}
.day-sep span{background:var(--surf);border:1px solid var(--border);padding:3px 12px;border-radius:10px}
.msg{display:flex;gap:8px;max-width:min(78%,560px);margin-top:6px;animation:pop .12s ease}
@keyframes pop{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.msg.own{align-self:flex-end;flex-direction:row-reverse}
.msg .m-av{flex:none;margin-top:4px}
.bubble{
  background:var(--surf);border:1px solid var(--border);border-radius:16px;
  padding:8px 12px;font-size:15px;line-height:1.4;word-wrap:break-word;overflow-wrap:break-word;
  box-shadow:0 1px 2px var(--shadow);
}
.msg.own .bubble{background:var(--own-grad);border:none;color:#fff;border-bottom-right-radius:6px}
.msg:not(.own) .bubble{border-bottom-left-radius:6px}
.b-sender{font-size:12px;font-weight:700;margin-bottom:2px;color:var(--accent2)}
.b-text{white-space:pre-wrap}
.msg.own .b-text{color:#fff}
.b-file{
  display:flex;align-items:center;gap:10px;padding:6px 0 2px;text-decoration:none;color:var(--text);
}
.msg.own .b-file{color:#fff}
.f-ico{
  width:40px;height:40px;border-radius:10px;background:rgba(0,0,0,.12);flex:none;
  display:flex;align-items:center;justify-content:center;font-size:19px;
}
.f-name{font-weight:600;font-size:13px;max-width:220px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.f-size{font-size:11px;opacity:.7}
.b-img{display:block;max-width:min(100%,380px);max-height:320px;border-radius:12px;margin-left:-4px;margin-top:2px;cursor:pointer}
.b-meta{display:flex;align-items:center;justify-content:flex-end;gap:5px;margin-top:4px;font-size:11px;opacity:.85;min-height:14px}
.msg.own .b-meta{opacity:1}
.ticks{font-size:13px;letter-spacing:-2px;color:#fff}
.ticks.pending{opacity:.9}
.ticks.read{color:#8ef0c8}
.typing-line{max-width:820px;margin:0 auto;height:20px;padding:2px 8px;font-size:13px;color:var(--muted);display:flex;align-items:center;gap:6px}
.typing-line .tdots span{display:inline-block;width:5px;height:5px;border-radius:50%;background:var(--muted);margin-right:3px;animation:blink 1.2s infinite}
.typing-line .tdots span:nth-child(2){animation-delay:.2s}
.typing-line .tdots span:nth-child(3){animation-delay:.4s}
@keyframes blink{0%,100%{opacity:.25}50%{opacity:1}}

.chat-input{
  border-top:1px solid var(--border);background:var(--bg2);padding:10px 16px calc(14px + env(safe-area-inset-bottom));
}
.in-row{max-width:820px;margin:0 auto;display:flex;align-items:flex-end;gap:8px}
.attach-btn{flex:none;height:42px;min-width:42px;display:flex;align-items:center;justify-content:center;font-size:19px;color:var(--muted)}
.attach-btn:hover{color:var(--text)}
.ta-wrap{flex:1;background:var(--surf);border:1px solid var(--border);border-radius:14px;display:flex;align-items:flex-end;padding:6px 14px}
.ta-wrap:focus-within{border-color:var(--accent)}
#ta{
  width:100%;max-height:130px;background:transparent;border:none;outline:none;resize:none;
  font-size:15px;line-height:1.4;padding:6px 0;
}
.send-btn{
  flex:none;width:42px;height:42px;border-radius:50%;background:var(--own-grad);color:#fff;
  display:flex;align-items:center;justify-content:center;font-size:18px;transition:filter .15s;
}
.send-btn:hover{filter:brightness(1.1)}
.send-btn:disabled{opacity:.45;cursor:default}

/* ---------- модалки ---------- */
.overlay{
  position:fixed;inset:0;background:rgba(5,7,15,.6);backdrop-filter:blur(3px);
  display:flex;align-items:center;justify-content:center;z-index:100;padding:16px;
}
.modal{
  width:min(420px,94vw);max-height:88vh;overflow-y:auto;background:var(--surf);
  border:1px solid var(--border);border-radius:20px;box-shadow:0 24px 60px var(--shadow);animation:pop .15s ease;
}
.modal-head{display:flex;align-items:center;padding:18px 20px 4px;font-weight:700;font-size:17px;gap:10px}
.modal-head .grow{flex:1}
.modal-body{padding:16px 20px 22px}
.pf-row{display:flex;gap:16px;align-items:center;margin-bottom:16px}
.pf-info{flex:1;min-width:0}
.pf-username{color:var(--muted);font-size:13px}
.avatar.lg{width:72px;height:72px;font-size:26px}
.lbl{font-size:13px;color:var(--muted);font-weight:600;margin:12px 0 6px;display:block}
.gm-item{display:flex;align-items:center;gap:10px;padding:9px 6px;border-radius:10px;cursor:pointer;flex-wrap:wrap}
.gm-item:hover{background:var(--surf2)}
.gm-item input{accent-color:var(--accent);width:17px;height:17px}
.gm-name{flex:1;font-size:14px;font-weight:600}
.gm-un{color:var(--muted);font-size:12px}
.divider{height:1px;background:var(--border);margin:12px 0}

/* ---------- служебные/удалённые/голосовые ---------- */
.sys-msg{
  align-self:center;text-align:center;color:var(--muted);font-size:12.5px;margin:10px 0;
  background:var(--surf);border:1px solid var(--border);border-radius:12px;padding:6px 14px;
  max-width:min(90%,520px);white-space:pre-wrap;word-wrap:break-word;
}
.m-del{opacity:0;transition:opacity .15s;font-size:11px;margin-left:6px;color:inherit}
.msg:hover .m-del{opacity:.75}
.bubble.del .b-text{opacity:.55;font-style:italic}
.m-del{background:none;border:none;cursor:pointer;padding:0;line-height:1;font-size:13px}
.pf-spec{font-size:12.5px;color:var(--muted);margin-top:6px}
.adm-ctrl{display:flex;gap:6px;margin-bottom:8px}
.adm-ctrl select{flex:1;background:var(--surf2);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:6px 8px;font-size:13px;min-width:0}
.adn{display:flex;align-items:center;gap:8px;margin-top:10px}
.adn .btn{padding:6px 10px;font-size:12px}
.adm-page{flex:1;text-align:center;font-size:12px;color:var(--muted)}
.blocked-banner{
  max-width:820px;margin:8px auto 0;text-align:center;
  background:rgba(239,68,68,.12);color:#f87171;border:1px solid rgba(239,68,68,.3);
  border-radius:10px;padding:8px 12px;font-size:13px;
}
.rec-bar{
  max-width:820px;margin:0 auto 6px;display:flex;align-items:center;gap:10px;
  background:var(--surf);border:1px solid var(--border);border-radius:12px;
  padding:8px 12px;font-size:13px;color:var(--muted);
}
.rec-dot{width:10px;height:10px;border-radius:50%;background:var(--danger);animation:blink 1s infinite;flex:none}
.rec-bar .icon-btn{width:30px;height:30px;font-size:13px}
.vbox{display:flex;align-items:center;gap:10px;min-width:210px;max-width:280px;flex-direction:column;align-items:stretch;padding:2px 0}
.v-top{display:flex;align-items:center;gap:10px}
.v-btn{
  width:36px;height:36px;border-radius:50%;background:rgba(0,0,0,.16);flex:none;
  display:flex;align-items:center;justify-content:center;font-size:13px;transition:filter .15s;
}
.msg.own .v-btn{background:rgba(255,255,255,.2)}
.v-btn:hover{filter:brightness(1.2)}
.v-wave{flex:1;height:30px;display:flex;align-items:center;gap:2px;cursor:pointer;position:relative}
.v-bar{flex:1;min-width:2px;border-radius:2px;background:currentColor;opacity:.5}
.v-prog{position:absolute;left:0;top:0;height:100%;background:var(--accent);opacity:.3;width:var(--p,0%);pointer-events:none}
.v-bottom{display:flex;align-items:center;gap:8px;font-size:11px;opacity:.85;margin-top:2px}
.v-speed{border:1px solid rgba(128,128,128,.4);border-radius:6px;padding:0 6px;font-size:11px;line-height:18px}
.admin-note{font-size:12px;color:var(--muted);padding:8px 12px;border:1px dashed var(--border);border-radius:10px;max-width:820px;margin:0 auto 6px;text-align:center}

/* ---------- мобильная версия ---------- */
@media (max-width:760px){
  .sidebar{width:100%;min-width:0}
  .chat-panel{position:fixed;inset:0;transform:translateX(100%);transition:transform .22s ease;z-index:40}
  .chat-panel.show{transform:none}
  .ch-back{display:flex}
  .msgs-inner{max-width:none}
  #view-auth{background:
    radial-gradient(600px 400px at 80% -10%, rgba(124,108,255,.2), transparent 60%),
    var(--bg)}
}
</style>
</head>
<body>

<div id="view-auth" style="display:none">
  <div class="auth-card">
    <div class="auth-logo"><span class="dot"></span>Lowkey</div>
    <div class="err" id="auth-err"></div>
    <div class="tabs">
      <button id="tab-login" class="on">Вход</button>
      <button id="tab-reg">Регистрация</button>
    </div>
    <div id="auth-login">
      <div class="field"><label>Username</label><input id="li-user" autocomplete="username" placeholder="например: alice"></div>
      <div class="field"><label>Пароль</label><input id="li-pass" type="password" autocomplete="current-password" placeholder="••••••••"></div>
      <button class="btn btn-primary" id="li-btn">Войти</button>
    </div>
    <div id="auth-reg" style="display:none">
      <div class="field"><label>Username</label><input id="rg-user" autocomplete="username" placeholder="3–20 символов: латиница, цифры, _"></div>
      <div class="field"><label>Имя (как вас видят)</label><input id="rg-name" placeholder="Например: Алиса"></div>
      <div class="field"><label>Пароль</label><input id="rg-pass" type="password" autocomplete="new-password" placeholder="минимум 6 символов"></div>
      <button class="btn btn-primary" id="rg-btn">Создать аккаунт</button>
    </div>
  </div>
</div>

<div id="view-app">
  <div class="sidebar">
    <div class="sb-top">
      <div class="sb-logo"><span class="dot"></span>Lowkey</div>
      <button class="icon-btn" id="btn-admin" title="Админ-панель" style="display:none">&#9881;</button>
      <button class="icon-btn" id="btn-group" title="Создать">+</button>
      <button class="icon-btn" id="btn-theme" title="Тема">&#9679;</button>
      <button class="icon-btn" id="btn-profile" title="Профиль">
        <span id="sb-avatar-wrap"></span>
      </button>
    </div>
    <div class="search-wrap">
      <span class="ico">&#128269;</span>
      <input id="search-input" placeholder="Поиск людей по username…" autocomplete="off">
      <div class="search-res" id="search-res"></div>
    </div>
    <div class="chat-list" id="chat-list"></div>
  </div>

  <div class="chat-panel" id="chat-panel">
    <div class="chat-head">
      <button class="icon-btn ch-back" id="btn-back" title="Назад">&#8592;</button>
      <span id="ch-avatar-wrap"></span>
      <div class="ch-title">
        <div class="ch-name" id="ch-name">Выберите чат</div>
        <div class="ch-status" id="ch-status"></div>
      </div>
      <div class="ch-actions">
        <button class="icon-btn" id="btn-ch-profile" title="Участники / профиль">&#9432;</button>
      </div>
    </div>
    <div class="msgs" id="msgs"><div class="msgs-inner" id="msgs-inner"></div></div>
    <div class="typing-line" id="typing-line" style="display:none"><span class="tdots"><span></span><span></span><span></span></span><span id="typing-text"></span></div>
    <div id="blocked-banner" class="blocked-banner" style="display:none"></div>
    <div class="chat-input" id="chat-input">
      <div class="rec-bar" id="rec-bar" style="display:none">
        <span class="rec-dot" id="rec-dot"></span>
        <span style="font-weight:600">Запись</span>
        <span id="rec-time">0:00</span>
        <span id="rec-lvl" style="flex:1;height:4px;background:var(--surf2);border-radius:2px;overflow:hidden">
          <span id="rec-lvl-fill" style="display:block;height:100%;width:0%;background:var(--danger);border-radius:2px"></span>
        </span>
        <button class="icon-btn" id="rec-cancel" title="Отменить">&#10005;</button>
      </div>
      <div class="in-row">
        <input type="file" id="file-input" style="display:none">
        <button class="attach-btn" id="btn-attach" title="Прикрепить файл">&#128206;</button>
        <div class="ta-wrap"><textarea id="ta" rows="1" placeholder="Сообщение…"></textarea></div>
        <button class="attach-btn" id="btn-mic" title="Голосовое сообщение">&#127908;</button>
        <button class="send-btn" id="btn-send" title="Отправить">&#10148;</button>
      </div>
    </div>
  </div>
</div>

<script>
'use strict';
/* ==== помощники ==== */
function $(s){return document.querySelector(s)}
function h(tag, attrs){
  var e=document.createElement(tag);
  if(attrs) for(var k in attrs){
    var v=attrs[k];
    if(v==null) continue;
    if(k==='class') e.className=v;
    else if(k==='text') e.textContent=v;
    else if(k.indexOf('on')===0 && typeof v==='function') e.addEventListener(k.slice(2),v);
    else e.setAttribute(k,v);
  }
  for(var i=2;i<arguments.length;i++){
    var c=arguments[i];
    if(c==null) continue;
    if(Array.isArray(c)) c.forEach(function(x){if(x!=null)e.appendChild(typeof x==='string'?document.createTextNode(x):x)});
    else e.appendChild(typeof c==='string'?document.createTextNode(c):c);
  }
  return e;
}
function fmtTime(t){return new Date(t).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'})}
function fmtDay(t){
  var d=new Date(t),n=new Date(),y=new Date(n);y.setDate(y.getDate()-1);
  if(d.toDateString()===n.toDateString())return 'Сегодня';
  if(d.toDateString()===y.toDateString())return 'Вчера';
  return d.toLocaleDateString('ru-RU',{day:'numeric',month:'long'});
}
function fmtLastSeen(t){
  if(!t)return null;
  var diff=Date.now()-t;
  var min=Math.floor(diff/60000);
  if(min<1)return 'только что';
  if(min<60)return 'был(а) '+min+' мин назад';
  var hh=Math.floor(min/60);
  if(hh<24){var d=new Date(t);return 'был(а) сегодня в '+fmtTime(t)}
  var dd=Math.floor(hh/24);
  if(dd===1)return 'был(а) вчера';
  if(dd<7)return 'был(а) '+dd+' дн(я) назад';
  return 'был(а) '+new Date(t).toLocaleDateString('ru-RU',{day:'numeric',month:'short'});
}
function fmtSize(b){
  if(!b)return '';
  if(b<1024)return b+' Б';
  if(b<1048576)return (b/1024).toFixed(1)+' КБ';
  return (b/1048576).toFixed(1)+' МБ';
}
var PALETTE=['#f59e0b','#10b981','#8b5cf6','#3b82f6','#ec4899','#f43f5e','#14b8a6','#6366f1','#f97316','#06b6d4'];
function initials(name){
  var parts=String(name||'?').trim().split(/\s+/);
  var s=(parts[0]||'').charAt(0)+(parts[1]?parts[1].charAt(0):'');
  return s.toUpperCase()||'?';
}
function avatarStyle(u){
  return 'background:'+PALETTE[Math.abs((u&&u.id||0)%PALETTE.length)];
}
function avatarEl(u,size){
  var cls='avatar'+(size?' '+size:'');
  var e=h('span',{class:cls,style:avatarStyle(u)});
  if(u&&u.avatar)e.appendChild(h('img',{src:u.avatar}));
  else e.appendChild(document.createTextNode(initials(u?u.displayName||u.username:'?')));
  return e;
}

/* ==== состояние ==== */
var S={
  token:localStorage.getItem('lowkey_token')||'',
  me:null,
  ws:null,
  chats:[],
  chatId:null,
  msgsById:{},
  firstLoadedId:null,
  typingTimer:null,
  lastTypingSent:0,
  searchTimer:null,
  unreadTotal:0,
  msgSeq:0,
  loadingOlder:false
};

/* ==== API ==== */
function api(url,opt){
  opt=opt||{};
  opt.headers=opt.headers||{};
  if(S.token)opt.headers['Authorization']='Bearer '+S.token;
  return fetch(url,opt).then(function(r){
    return r.json().catch(function(){return {error:'Ошибка соединения'}}).then(function(d){
      if(!r.ok){var e=new Error((d&&d.error)||('Ошибка '+r.status));e.status=r.status;throw e}
      return d;
    });
  });
}

/* ==== тема ==== */
function applyTheme(){
  var t=localStorage.getItem('lowkey_theme')||'dark';
  document.documentElement.setAttribute('data-theme',t);
  $('#btn-theme').textContent=(t==='dark')?'☀':'☾';
}
applyTheme();
$('#btn-theme').onclick=function(){
  var cur=document.documentElement.getAttribute('data-theme');
  var next=(cur==='dark')?'light':'dark';
  localStorage.setItem('lowkey_theme',next);
  applyTheme();
};

/* ==== экраны ==== */
function showAuth(){ $('#view-auth').style.display='flex'; $('#view-app').classList.remove('show'); }
function showApp(){
  $('#view-auth').style.display='none';
  $('#view-app').classList.add('show');
  $('#sb-avatar-wrap').innerHTML='';
  $('#sb-avatar-wrap').appendChild(avatarEl(S.me,'xs'));
  showAdminBtn();
}

/* ==== вход/регистрация ==== */
var AUTH_MODE='login';
function setAuthMode(m){
  AUTH_MODE=m;
  $('#tab-login').className=(m==='login')?'on':'';
  $('#tab-reg').className=(m==='reg')?'on':'';
  $('#auth-login').style.display=(m==='login')?'':'none';
  $('#auth-reg').style.display=(m==='reg')?'':'none';
}
$('#tab-login').onclick=function(){setAuthMode('login')};
$('#tab-reg').onclick=function(){setAuthMode('reg')};
function showErr(msg){var e=$('#auth-err');e.textContent=msg;e.className='err show'}
function hideErr(){$('#auth-err').className='err'}
$('#li-btn').onclick=function(){
  hideErr();
  var u=$('#li-user').value.trim(),p=$('#li-pass').value;
  if(!u||!p)return showErr('Введите username и пароль');
  api('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})})
    .then(function(d){afterAuth(d)}).catch(function(e){showErr(e.message)});
};
$('#rg-btn').onclick=function(){
  hideErr();
  var u=$('#rg-user').value.trim(),n=$('#rg-name').value.trim(),p=$('#rg-pass').value;
  if(!u)return showErr('Введите username');
  if(!p||p.length<6)return showErr('Пароль — минимум 6 символов');
  api('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p,displayName:n})})
    .then(function(d){afterAuth(d)}).catch(function(e){showErr(e.message)});
};
['#li-user','#li-pass','#rg-user','#rg-pass'].forEach(function(s){
  $(s).addEventListener('keydown',function(ev){if(ev.key==='Enter'){if(AUTH_MODE==='login')$('#li-btn').click();else$('#rg-btn').click();}});
});
function afterAuth(d){
  S.token=d.token;
  S.me=d.user;
  localStorage.setItem('lowkey_token',S.token);
  showApp();
  connectWs();
  renderSidebar();
  handleDeepLink();
}
function showAdminBtn(){
  $('#btn-admin').style.display=(S.me&&S.me.role==='admin')?'':'none';
}
$('#btn-admin').onclick=openAdminPanel;
function logout(){
  api('/api/logout',{method:'POST'}).catch(function(){});
  try{S.ws&&S.ws.close()}catch(e){}
  S.token='';S.me=null;S.chats=[];S.chatId=null;
  localStorage.removeItem('lowkey_token');
  showAuth();
}
$('#btn-profile').onclick=openProfile;
$('#btn-group').onclick=openCreateMenu;

/* ==== WebSocket ==== */
function connectWs(){
  if(!S.token)return;
  var proto=(location.protocol==='https:')?'wss':'ws';
  var ws=new WebSocket(proto+'://'+location.host+'/ws');
  S.ws=ws;
  ws.onopen=function(){ws.send(JSON.stringify({type:'auth',token:S.token}))};
  ws.onmessage=function(ev){var d;try{d=JSON.parse(ev.data)}catch(e){return}handleWS(d)};
  ws.onclose=function(){
    setTimeout(function(){if(S.token)connectWs()},2500);
  };
  ws.onerror=function(){};
}
function handleWS(d){
  switch(d.type){
    case 'init':
      S.me=d.me;
      S.chats=d.chats||[];
      renderSidebar();
      if(!S.chatId&&S.chats.length)selectChat(S.chats[0].id,true);
      handleDeepLink();
      break;
    case 'message':
      onWsMessage(d.message);
      break;
    case 'message_deleted':
      onMsgDeleted(d);
      break;
    case 'blocks_updated':
      onBlocksUpdated(d);
      break;
    case 'status':
      onWsStatus(d);
      break;
    case 'typing':
      onWsTyping(d);
      break;
    case 'presence':
    case 'profile_updated':
      upsertPresence(d.user);
      break;
    case 'chat_updated':
      upsertChat(d.chat);
      break;
    case 'error':
      if(d.code==='blocked'){
        alert('Ваш аккаунт заблокирован администратором');
        logout();
      }else if(d.code==='unauthorized'){
        logout();
      }else if(d.message){
        alert(d.message);
      }
      break;
    default:break;
  }
}
function onMsgDeleted(d){
  var chat=S.chats.find(function(c){return c.id===d.chatId});
  if(chat&&chat.lastMessage&&chat.lastMessage.id===d.messageId){
    chat.lastMessage.deleted=true;
    chat.lastMessage.text='';
    chat.lastMessage.file=null;
    chat.lastMessage.voice=null;
    renderSidebar();
  }
  var m=S.msgsById[d.messageId];
  if(m){m.deleted=true;updateMsgDom(m)}
}
function onBlocksUpdated(d){
  S.chats.forEach(function(c){
    if(c.type==='private'&&c.members&&c.members.some(function(m){return m.id===d.userId})){
      if(d.blocked)c.blocked='them';
      else if(c.blocked==='them')c.blocked=null;
    }
  });
  renderSidebar();
  if(S.chatId)renderChatHead();
}
function wsSend(obj){if(S.ws&&S.ws.readyState===1)S.ws.send(JSON.stringify(obj))}

function onWsMessage(m){
  var chat=S.chats.find(function(c){return c.id===m.chatId});
  if(!chat){return}
  if(m.chatId===S.chatId){
    appendMessage(m);
    markSeen(m.chatId);
  }else{
    chat.unreadCount=(chat.unreadCount||0)+1;
    if(m.senderId===S.me.id)chat.unreadCount=0;
  }
  if(chat.lastMessage&&m.id>chat.lastMessage.id)chat.lastMessage={id:m.id,senderId:m.senderId,text:m.text,file:m.file,voice:m.voice,deleted:!!m.deleted,createdAt:m.createdAt};
  else if(!chat.lastMessage)chat.lastMessage={id:m.id,senderId:m.senderId,text:m.text,file:m.file,voice:m.voice,deleted:!!m.deleted,createdAt:m.createdAt};
  renderChatListOrder();
  renderSidebar();
  updateTitle();
}
function daySep(t){
  return h('div',{class:'day-sep'},[h('span',{text:fmtDay(t)})]);
}
function wrapLastDate(){
  var els=$('#msgs-inner').querySelectorAll('[data-ts]');
  return els.length?els[els.length-1].getAttribute('data-ts'):null;
}
function appendMessage(m){
  if(S.msgsById[m.id])return;
  S.msgsById[m.id]=m;
  var wrap=$('#msgs-inner');
  var lastDate=wrapLastDate();
  if(!lastDate||new Date(lastDate).toDateString()!==new Date(m.createdAt).toDateString()){
    wrap.appendChild(daySep(m.createdAt));
  }
  wrap.appendChild(msgElem(m));
  scrollBottom();
}
function onWsStatus(d){
  var el=document.querySelector('.msg[data-id="'+d.messageId+'"] .ticks');
  if(el){
    if(d.status==='read')el.className='ticks read';
    else if(d.status==='delivered')el.className='ticks pending';
    var cnt=el.parentNode.querySelector('.t-count');
    if(cnt&&d.status==='read')cnt.textContent='  '+d.readBy.length;
  }
  var lm=S.msgsById[d.messageId];
  if(lm){lm.status=d.status;lm.readBy=d.readBy}
}
function onWsTyping(d){
  if(d.chatId!==S.chatId)return;
  var line=$('#typing-line');
  if(d.typing){line.style.display='flex';$('#typing-text').textContent=d.name+' печатает…'}
  else if(line.style.display!=='none'){line.style.display='none'}
}
function upsertPresence(u){
  var chat=S.chats.find(function(c){return c.type==='private'&&c.members.some(function(m){return m.id===u.id})});
  if(!chat)return;
  chat.members=chat.members.map(function(m){return(m.id===u.id)?u:m});
  renderSidebar();
  if(chat.id===S.chatId)renderChatHead();
}
function upsertChat(c){
  var i=S.chats.findIndex(function(x){return x.id===c.id});
  if(i>=0)S.chats[i]=c;else S.chats.push(c);
  renderChatListOrder();
  renderSidebar();
  updateTitle();
  if(c.id===S.chatId)renderChatHead();
}

/* ==== список чатов ==== */
function renderSidebar(){
  var list=$('#chat-list');
  list.innerHTML='';
  S.chats.forEach(function(c){list.appendChild(chatItemEl(c))});
  updateTitle();
}
function chatItemEl(c){
  var av;
  if(c.type==='private'){
    var other=c.members.find(function(m){return m.id!==S.me.id});
    av=avatarEl(other||{displayName:'?'},null);
    if(other&&other.online)av.appendChild(h('span',{class:'online-dot'}));
  }else{
    av=avatarEl({id:c.id,displayName:c.name,avatar:c.avatar},null);
  }
  var prev='';
  if(c.lastMessage){
    var sender=c.lastMessage.senderId===S.me.id?'Вы: ':'';
    if(c.lastMessage.deleted)prev=sender+'Сообщение удалено';
    else if(c.lastMessage.voice)prev=sender+'[Голосовое]';
    else if(c.lastMessage.file)prev=sender+(c.lastMessage.file.type&&c.lastMessage.file.type.indexOf('image')===0?'[Изображение]':'[Файл]');
    else prev=sender+c.lastMessage.text;
  }else prev='Нет сообщений';
  var item=h('div',{class:'cl-item'+(c.id===S.chatId?' active':''),onclick:function(){selectChat(c.id)},'data-id':c.id},[
    av,
    h('div',{class:'cl-main'},[
      h('div',{class:'cl-top'},[
        h('div',{class:'cl-name',text:c.name}),
        h('div',{class:'cl-time',text:c.lastMessage?fmtTime(c.lastMessage.createdAt):''})
      ]),
      h('div',{class:'cl-bot'},[
        h('div',{class:'cl-prev',text:prev}),
        c.unreadCount>0?h('span',{class:'badge',text:''+c.unreadCount}):null
      ])
    ])
  ]);
  return item;
}
function renderChatListOrder(){
  S.chats.sort(function(a,b){
    var ta=a.lastMessage?a.lastMessage.createdAt:a.createdAt;
    var tb=b.lastMessage?b.lastMessage.createdAt:b.createdAt;
    return tb-ta;
  });
}
function updateTitle(){
  var unread=S.chats.reduce(function(s,c){return s+(c.unreadCount||0)},0);
  S.unreadTotal=unread;
  document.title=unread>0?'('+unread+') Lowkey':'Lowkey';
}

/* ==== выбор чата ==== */
function selectChat(id,skipUnread){
  stopVoice();
  S.chatId=id;
  var chat=S.chats.find(function(c){return c.id===id});
  $('#chat-panel').classList.add('show');
  if(chat)chat.unreadCount=0;
  renderSidebar();
  renderChatHead();
  $('#msgs-inner').innerHTML='';
  S.msgsById={};
  S.firstLoadedId=null;
  loadMessages(id,0);
  if(!skipUnread)markSeen(id);
  $('#ta').focus();
}
$('#btn-back').onclick=function(){
  $('#chat-panel').classList.remove('show');
  S.chatId=null;
  renderChatListOrder();
  renderSidebar();
};
function renderChatHead(){
  var chat=S.chats.find(function(c){return c.id===S.chatId});
  if(!chat)return;
  var wrap=$('#ch-avatar-wrap');
  wrap.innerHTML='';
  var sub='';
  if(chat.type==='private'){
    var other=chat.members.find(function(m){return m.id!==S.me.id});
    wrap.appendChild(avatarEl(other||{displayName:'?'},'small'));
    if(other){
      sub=other.online?'онлайн':(fmtLastSeen(other.lastSeen)||'');
      $('#ch-status').className='ch-status'+(other.online?' online':'');
      if(other.blocked){sub='заблокирован';$('#ch-status').className='ch-status'}
    }
    if(chat.blocked)sub=chat.blocked==='me'?'вы заблокировали пользователя':'пользователь заблокировал вас';
  }else if(chat.type==='channel'){
    wrap.appendChild(avatarEl({id:chat.id,displayName:chat.name,avatar:chat.avatar},'small'));
    sub='#'+(chat.handle||'')+(chat.visibility==='private'?' · приватный':'')+' · '+(chat.members?chat.members.length:0)+' подписчиков';
    $('#ch-status').className='ch-status';
  }else{
    wrap.appendChild(avatarEl({id:chat.id,displayName:chat.name,avatar:chat.avatar},'small'));
    sub=(chat.type==='system'?'служебный чат':'группа')+' · '+(chat.members?chat.members.length:0)+' участников';
    $('#ch-status').className='ch-status';
  }
  $('#ch-name').textContent=chat.name;
  $('#ch-status').textContent=sub;
  updateInputState();
}
$('#btn-ch-profile').onclick=function(){
  var chat=S.chats.find(function(c){return c.id===S.chatId});
  if(!chat)return;
  if(chat.type==='private'){
    var other=chat.members.find(function(m){return m.id!==S.me.id});
    if(other)openUserCard(other);
  }else{
    openGroupInfo(chat);
  }
};

/* ==== сообщения ==== */
function loadMessages(chatId,before){
  var url='/api/chats/'+chatId+'/messages?limit=35'+(before?('&before='+before):'');
  api(url).then(function(list){
    if(!list||!list.length){if(!before&&!S.firstLoadedId)emptyChat();return}
    var wrap=$('#msgs-inner');
    if(!before){
      wrap.innerHTML='';
      S.msgsById={};
    }
    for(var i=0;i<list.length;i++){
      var m=list[i];
      var el=msgElem(m);
      S.msgsById[m.id]=m;
      if(!before){
        var prev=list[i-1];
        if(!prev||new Date(prev.createdAt).toDateString()!==new Date(m.createdAt).toDateString()){
          wrap.appendChild(daySep(m.createdAt));
        }
        wrap.appendChild(el);
      }else{
        var newer=list[i+1];
        if(!newer||new Date(newer.createdAt).toDateString()!==new Date(m.createdAt).toDateString()){
          wrap.insertBefore(daySep(m.createdAt),wrap.firstChild);
        }
        wrap.insertBefore(el,wrap.firstChild);
      }
    }
    S.firstLoadedId=list[0].id;
    S.loadingOlder=false;
    if(!before){scrollBottom(0);S.loadingOlder=false;markSeen(chatId)}
    else{var first=wrap.firstChild;if(first)first.scrollIntoView({block:'start'})}
  }).catch(function(e){S.loadingOlder=false});
}
function emptyChat(){
  var wrap=$('#msgs-inner');
  wrap.innerHTML='';
  wrap.appendChild(h('div',{class:'day-sep'},[h('span',{text:'Напишите первое сообщение'})]));
}
function markSeen(chatId){
  var ids=[];
  for(var id in S.msgsById){
    var m=S.msgsById[id];
    if(m.senderId!==S.me.id&&(m.readBy||[]).indexOf(S.me.id)<0&&ids.length<60)ids.push(m.id);
  }
  if(ids.length)wsSend({type:'read',chatId:chatId,messageIds:ids});
}
function msgElem(m){
  var own=m.senderId===S.me.id;
  var chat=S.chats.find(function(c){return c.id===m.chatId});
  if(m.system||m.kind==='system'){
    return h('div',{class:'sys-msg','data-id':m.id,'data-ts':m.createdAt},[h('span',{text:m.text})]);
  }
  var wrap=h('div',{class:'msg'+(own?' own':''),'data-id':m.id,'data-ts':m.createdAt});
  if(!own){
    var sender=(chat&&chat.members?chat.members.find(function(x){return x.id===m.senderId}):null)||{id:m.senderId,displayName:'#'+m.senderId};
    wrap.appendChild(h('div',{class:'m-av'},[avatarEl(sender,'xs')]));
  }
  var bubble=h('div',{class:'bubble'+(m.deleted?' del':'')},[]);
  if(m.deleted){
    bubble.appendChild(h('div',{class:'b-text',text:'Сообщение удалено'}));
  }else{
    if(!own&&chat&&chat.isGroup){
      var snd=(chat.members?chat.members.find(function(x){return x.id===m.senderId}):null);
      if(snd)bubble.appendChild(h('div',{class:'b-sender',text:snd.displayName||snd.username}));
    }
    if(m.voice)bubble.appendChild(voiceElem(m));
    if(m.file){
      var isImg=m.file.type&&m.file.type.indexOf('image')===0;
      if(isImg){
        bubble.appendChild(h('img',{class:'b-img',src:m.file.url,onclick:function(){window.open(m.file.url,'_blank')}}));
      }else{
        bubble.appendChild(h('a',{class:'b-file',href:m.file.url,target:'_blank'},[
          h('span',{class:'f-ico',text:'📎'}),
          h('span',{},[h('div',{class:'f-name',text:m.file.name}),h('div',{class:'f-size',text:fmtSize(m.file.size)})])
        ]));
      }
    }
    if(m.text)bubble.appendChild(h('div',{class:'b-text',text:m.text}));
  }
  var meta=h('div',{class:'b-meta'},[]);
  var time=document.createTextNode(fmtTime(m.createdAt));
  meta.appendChild(time);
  if(own&&!m.deleted){
    var t='✓';
    if(m.status==='delivered'||m.status==='read')t='✓✓';
    var ticks=h('span',{class:'ticks'+(m.status==='read'?' read':' pending'),text:t});
    meta.appendChild(ticks);
    if(chat&&chat.isGroup&&m.status==='read'&&m.readBy&&m.readBy.length>1){
      meta.appendChild(h('span',{class:'t-count',text:'  '+m.readBy.length}));
    }
  }
  if(!m.deleted&&(own||(S.me&&S.me.role==='admin'))){
    meta.appendChild(h('button',{class:'m-del',title:'Удалить',onclick:function(){delMessage(m)}},{text:'🗑'}));
  }
  bubble.appendChild(meta);
  wrap.appendChild(bubble);
  return wrap;
}

/* --- скролл --- */
var msgsEl=function(){return $('#msgs')};
function scrollBottom(force){
  var el=msgsEl();
  el.scrollTop=el.scrollHeight;
}
$('#msgs').addEventListener('scroll',function(){
  var el=this;
  if(el.scrollTop<40&&S.firstLoadedId&&S.chatId&&!S.loadingOlder){
    S.loadingOlder=true;
    loadMessages(S.chatId,S.firstLoadedId);
  }
});

/* ==== отправка ==== */
function sendMessage(text,file,voice){
  var chatId=S.chatId;
  if(!chatId)return;
  if(!text&&!file&&!voice)return;
  wsSend({type:'message',chatId:chatId,text:text,file:file,voice:voice});
}
$('#btn-send').onclick=function(){submitInput()};
['keydown','input'].forEach(function(ev){
  $('#ta').addEventListener(ev,function(e){
    if(e.type==='keydown'&&e.key==='Enter'&&!e.shiftKey){e.preventDefault();submitInput()}
    if(e.type==='input'){autoGrow();typingNotify()}
  });
});
function autoGrow(){
  var ta=$('#ta');
  ta.style.height='auto';
  ta.style.height=Math.min(ta.scrollHeight,130)+'px';
}
function submitInput(){
  var ta=$('#ta');
  var text=ta.value.trim();
  if(!text){return}
  sendMessage(text,null);
  ta.value='';
  autoGrow();
  typingNotify(false);
}
function typingNotify(on){
  if(!S.chatId)return;
  var now=Date.now();
  if(on&&(now-S.lastTypingSent)<900)return;
  S.lastTypingSent=now;
  wsSend({type:'typing',chatId:S.chatId,typing:on===false?false:true});
  clearTimeout(S.typingTimer);
  if(on!==false)S.typingTimer=setTimeout(function(){typingNotify(false)},1600);
}
$('#btn-attach').onclick=function(){$('#file-input').click()};
$('#file-input').onchange=function(){
  var f=this.files&&this.files[0];
  this.value='';
  if(!f||!S.chatId){return}
  var fd=new FormData();
  fd.append('file',f);
  var btn=$('#btn-send');btn.disabled=true;
  api('/api/upload',{method:'POST',body:fd}).then(function(d){
    btn.disabled=false;
    sendMessage('',{url:d.url,name:d.name,size:d.size,type:d.type});
  }).catch(function(e){btn.disabled=false;alert('Не удалось загрузить файл: '+e.message)});
};

/* ==== поиск людей ==== */
$('#search-input').addEventListener('input',function(){
  var q=this.value.trim();
  clearTimeout(S.searchTimer);
  var res=$('#search-res');
  if(!q){res.className='search-res';res.innerHTML='';return}
  S.searchTimer=setTimeout(function(){
    api('/api/users/search?q='+encodeURIComponent(q)).then(function(list){
      res.innerHTML='';
      if(!list.length){res.appendChild(h('div',{class:'sr-null',text:'Никого не нашли по «'+q+'»'}))}
      list.forEach(function(u){
        res.appendChild(h('button',{class:'sr-item',onclick:function(){
          res.className='search-res';$('#search-input').value='';
          openPrivate(u.id);
        }},[
          avatarEl(u,'small'),
          h('div',{class:'sr-meta'},[h('div',{class:'sr-name',text:u.displayName||u.username}),h('div',{class:'sr-un',text:'@'+u.username})]),
          u.online?h('span',{class:'badge',text:'онлайн'}):null
        ]));
      });
      res.className='search-res show';
    }).catch(function(){});
  },250);
});
document.addEventListener('click',function(ev){
  var res=$('#search-res');
  if(res&&!res.contains(ev.target)&&ev.target.id!=='search-input')res.className='search-res';
});
function openPrivate(userId){
  api('/api/chats/private',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({userId:userId})})
    .then(function(c){
      upsertChat(c);
      selectChat(c.id);
    }).catch(function(e){alert(e.message)});
}

function fmtDate(t){
  if(!t)return '';
  try{return new Date(t).toLocaleDateString('ru-RU',{day:'numeric',month:'short',year:'numeric'})}catch(e){return ''}
}

/* ==== меню «+» ==== */
function openCreateMenu(){
  var b=h('div',{},[]);
  function item(label,sub,fn){
    b.appendChild(h('button',{class:'btn btn-ghost',style:'width:100%;padding:14px;margin-bottom:10px;text-align:left;display:flex;flex-direction:column;align-items:flex-start;gap:2px',onclick:function(){closeOverlay(ov);fn()}},[
      h('div',{style:'font-weight:700',text:label}),
      sub?h('div',{class:'pf-username',text:sub}):null
    ]));
  }
  item('💬 Создать чат','Личный чат — по @username или ID',openPrivateCreate);
  item('👥 Создать группу','Общий чат с несколькими участниками',openGroupCreate);
  item('📢 Создать канал','Публичный или приватный — пишут только админы',openChannelCreate);
  if(S.me&&S.me.role==='admin')item('➕ Добавить пользователя','Найти человека по username или ID',openPrivateCreate);
  var ov=modal('Создать',b);
}

/* ==== личный чат по @username / ID ==== */
function openPrivateCreate(){
  var res=h('div',{},[]);
  var b=h('div',{},[]);
  b.appendChild(h('label',{class:'lbl',text:'@username или ID'}));
  b.appendChild(h('div',{class:'field'},[h('input',{id:'pc-q',placeholder:'alice или 42'})]));
  b.appendChild(res);
  res.appendChild(h('div',{class:'sr-null',text:'Начните вводить — появятся люди'}));
  var ov=modal('Новый личный чат',b);
  $('#pc-q').addEventListener('input',function(){
    var q=this.value.trim();
    if(!q){res.innerHTML='';res.appendChild(h('div',{class:'sr-null',text:'Начните вводить — появятся люди'}));return}
    api('/api/users/search?q='+encodeURIComponent(q)).then(function(list){
      res.innerHTML='';
      if(!list.length)res.appendChild(h('div',{class:'sr-null',text:'Никого не нашли. Проверьте username или ID'}));
      list.forEach(function(u){
        res.appendChild(h('button',{class:'sr-item',onclick:function(){
          api('/api/chats/private',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({userId:u.id})})
            .then(function(c){closeOverlay(ov);upsertChat(c);selectChat(c.id)})
            .catch(function(e){alert(e.message)});
        }},[avatarEl(u,'small'),h('div',{class:'sr-meta'},[
          h('div',{class:'sr-name',text:u.displayName||u.username}),
          h('div',{class:'sr-un',text:'@'+u.username+' · ID '+u.id})
        ])]));
      });
    }).catch(function(e){alert(e.message)});
  });
}

/* ==== создание канала ==== */
function openChannelCreate(){
  var b=h('div',{},[]);
  b.appendChild(h('label',{class:'lbl',text:'Название'}));
  b.appendChild(h('div',{class:'field'},[h('input',{id:'cc-name',placeholder:'Например: Новости'})]));
  b.appendChild(h('label',{class:'lbl',text:'@handle (уникальный, для ссылки-приглашения)'}));
  b.appendChild(h('div',{class:'field'},[h('input',{id:'cc-handle',placeholder:'my_news'})]));
  b.appendChild(h('label',{class:'lbl',text:'Описание'}));
  b.appendChild(h('div',{class:'field'},[h('input',{id:'cc-desc',placeholder:'О чём канал'})]));
  b.appendChild(h('div',{class:'divider'}));
  b.appendChild(h('label',{class:'gm-item'},[h('input',{type:'radio',name:'cc-vis',value:'public',checked:true}),h('div',{class:'gm-name',text:'Публичный'}),h('div',{class:'gm-un',text:'подписаться может любой по ссылке'})]));
  b.appendChild(h('label',{class:'gm-item'},[h('input',{type:'radio',name:'cc-vis',value:'private'}),h('div',{class:'gm-name',text:'Приватный'}),h('div',{class:'gm-un',text:'только по приглашению администратора'})]));
  b.appendChild(h('button',{class:'btn btn-primary',style:'margin-top:12px',onclick:function(){
    var vis=document.querySelector('input[name="cc-vis"]:checked');
    api('/api/channels',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      name:$('#cc-name').value.trim(),
      handle:$('#cc-handle').value.trim(),
      description:$('#cc-desc').value.trim(),
      visibility:vis?vis.value:'public'
    })}).then(function(c){closeOverlay(ov);upsertChat(c);selectChat(c.id)}).catch(function(e){alert(e.message)});
  }},{text:'Создать канал'}));
  var ov=modal('Новый канал',b);
}

/* ==== приглашение в канал ==== */
function openChannelInvite(c){
  var b=h('div',{},[]);
  b.appendChild(h('div',{class:'pf-row'},[
    h('div',{},[avatarEl({id:c.id,displayName:c.name,avatar:c.avatar},'lg')]),
    h('div',{class:'pf-info'},[
      h('div',{style:'font-weight:700;font-size:17px',text:c.name}),
      h('div',{class:'pf-username',text:'#'+c.handle}),
      h('div',{class:'ch-status',text:c.visibility==='private'?'Приватный · по приглашению':'Публичный'})
    ])
  ]));
  if(c.description)b.appendChild(h('div',{style:'font-size:14px;line-height:1.5',text:c.description}));
  b.appendChild(h('div',{class:'divider'}));
  b.appendChild(h('button',{class:'btn btn-primary',style:'width:100%',onclick:function(){
    api('/api/chats/'+c.id+'/join',{method:'POST'})
      .then(function(cc){closeOverlay(ov);upsertChat(cc);selectChat(cc.id)})
      .catch(function(e){alert(e.message)});
  }},{text:'Подписаться на канал'}));
  var ov=modal('Канал',b);
}
function copyText(t){
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(t).then(function(){alert('Ссылка скопирована в буфер')}).catch(function(){prompt('Скопируйте ссылку:',t)});
  }else prompt('Скопируйте ссылку:',t);
}
function inviteLinkFor(c){
  return location.origin+(location.pathname||'/')+'?join='+encodeURIComponent(c.handle||'');
}

/* ==== пригласить людей в группу/канал ==== */
function addChatMembers(chat){
  var res=h('div',{},[]);
  var b=h('div',{},[
    h('label',{class:'lbl',text:'Поиск людей по username'}),
    h('div',{class:'field'},[h('input',{id:'am-q',placeholder:'Например: alice'})]),
    res
  ]);
  var ov=modal('Пригласить в чат',b);
  $('#am-q').addEventListener('input',function(){
    var q=this.value.trim();if(!q){res.innerHTML='';return}
    api('/api/users/search?q='+encodeURIComponent(q)).then(function(list){
      res.innerHTML='';
      if(!list.length)res.appendChild(h('div',{class:'sr-null',text:'Никого не нашли'}));
      list.forEach(function(u){
        res.appendChild(h('button',{class:'sr-item',onclick:function(){
          api('/api/chats/'+chat.id+'/members',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({userIds:[u.id]})})
            .then(function(){closeOverlay(ov);api('/api/chats/'+chat.id).then(function(c){upsertChat(c)})})
            .catch(function(e){alert(e.message)});
        }},[avatarEl(u,'small'),h('div',{class:'sr-meta'},[h('div',{class:'sr-name',text:u.displayName||u.username}),h('div',{class:'sr-un',text:'@'+u.username})])]));
      });
    }).catch(function(){});
  });
}

/* ==== очистка истории / выход из чата ==== */
function clearHistory(chatId){
  if(!chatId)return;
  if(!confirm('Очистить историю? У других участников их копия останется.'))return;
  api('/api/chats/'+chatId+'/messages',{method:'DELETE'})
    .then(function(){$('#msgs-inner').innerHTML='';S.msgsById={};S.firstLoadedId=null;emptyChat()})
    .catch(function(e){alert(e.message)});
}
function leaveChat(chatId){
  if(!confirm('Покинуть чат?'))return;
  api('/api/chats/'+chatId+'/leave',{method:'POST'})
    .then(function(){
      var i=S.chats.findIndex(function(c){return c.id===chatId});
      if(i>=0)S.chats.splice(i,1);
      S.chatId=null;$('#chat-panel').classList.remove('show');
      renderSidebar();
    }).catch(function(e){alert(e.message)});
}

/* ==== голосовые сообщения: плеер ==== */
function fmtDur(s){s=Math.floor(s||0);var m=Math.floor(s/60);return m+':'+((s%60<10)?'0':'')+(s%60)}
function sampleWave(w,n){
  n=n||28;var out=[];
  if(!w||!w.length){for(var i=0;i<n;i++)out.push(.25+Math.random()*.5);return out}
  var step=Math.max(1,Math.floor(w.length/n));
  for(var i=0;i<n;i++){var idx=Math.min(w.length-1,i*step);var v=(w[idx]||0)/140;out.push(Math.min(1,Math.max(.06,v)))}
  return out;
}
function waveformEl(m){
  var el=h('div',{class:'v-wave'},[]);
  var bars=sampleWave(m.voice.wave,28);
  for(var i=0;i<bars.length;i++)el.appendChild(h('span',{class:'v-bar',style:'height:'+Math.max(3,Math.round(bars[i]*26))+'px'}));
  el.appendChild(h('span',{class:'v-prog'}));
  el.onclick=function(ev){seekVoice(m,ev,el)};
  return el;
}
function voiceElem(m){
  var box=h('div',{class:'vbox'},[]);
  var top=h('div',{class:'v-top'},[]);
  var btn=h('button',{class:'v-btn',text:'▶',onclick:function(){toggleVoice(m,btn)}});
  top.appendChild(btn);
  top.appendChild(waveformEl(m));
  var bottom=h('div',{class:'v-bottom'},[]);
  var cur=h('span',{class:'cur',text:'0:00'});
  var speed=h('button',{class:'v-speed',text:'1x',onclick:function(){
    var r=['1','1.5','2'];
    var i=r.indexOf(speed.textContent.split('x')[0]);
    var nx=r[(i+1)%r.length];
    speed.textContent=nx+'x';
    if(S.audio&&S.audio._mid===m.id)S.audio.playbackRate=parseFloat(nx);
  }});
  bottom.appendChild(cur);
  bottom.appendChild(speed);
  bottom.appendChild(h('span',{text:fmtDur(m.voice.duration)}));
  box.appendChild(top);
  box.appendChild(bottom);
  return box;
}
function stopVoice(){
  if(S.audio){try{S.audio.pause()}catch(e){}S.audio=null}
  if(S.voiceUI){
    if(S.voiceUI.btn)S.voiceUI.btn.textContent='▶';
    if(S.voiceUI.prog)S.voiceUI.prog.style.setProperty('--p','0%');
    if(S.voiceUI.cur)S.voiceUI.cur.textContent='0:00';
    S.voiceUI=null;
  }
}
function toggleVoice(m,btn){
  if(S.audio&&S.audio._mid===m.id&&!S.audio.paused){stopVoice();return}
  stopVoice();
  var box=btn.parentNode;
  var wv=box?box.querySelector('.v-wave'):null;
  var prog=wv?wv.querySelector('.v-prog'):null;
  var bottom=box?box.querySelector('.v-bottom'):null;
  var cur=bottom?bottom.querySelector('.cur'):null;
  var speed=bottom?bottom.querySelector('.v-speed'):null;
  var a=new Audio(m.voice.url);
  a._mid=m.id;
  if(speed)a.playbackRate=parseFloat(speed.textContent.split('x')[0])||1;
  a.ontimeupdate=function(){
    if(prog&&m.voice.duration)prog.style.setProperty('--p',(a.currentTime/m.voice.duration*100)+'%');
    if(cur)cur.textContent=fmtDur(a.currentTime);
  };
  a.onended=function(){stopVoice()};
  a.onerror=function(){stopVoice();alert('Не удалось воспроизвести голосовое')};
  S.audio=a;
  S.voiceUI={btn:btn,prog:prog,cur:cur};
  a.play().then(function(){btn.textContent='⏸'}).catch(function(){stopVoice()});
}
function seekVoice(m,ev,el){
  if(!S.audio||S.audio._mid!==m.id)return;
  var r=el.getBoundingClientRect();
  var p=Math.min(1,Math.max(0,(ev.clientX-r.left)/r.width));
  try{S.audio.currentTime=p*(m.voice.duration||0)}catch(e){}
}

/* ==== запись голосового ==== */
function startRec(){
  if(!S.chatId)return;
  if(!window.MediaRecorder){alert('Ваш браузер не поддерживает запись голоса. Используйте Chrome, Edge или Firefox');return}
  if(!navigator.mediaDevices||!navigator.mediaDevices.getUserMedia){alert('Браузер не даёт доступ к микрофону');return}
  navigator.mediaDevices.getUserMedia({audio:true}).then(function(stream){
    var r={stream:stream,chunks:[],start:Date.now(),timer:0,wave:[],cancel:false};
    var rec=new MediaRecorder(stream,{mimeType:'audio/webm;codecs=opus'});
    r.rec=rec;
    rec.ondataavailable=function(e){if(e.data&&e.data.size)r.chunks.push(e.data)};
    rec.onstop=function(){onRecStop(r)};
    rec.start(250);
    S.rec=r;
    $('#rec-bar').style.display='flex';
    $('#rec-time').textContent='0:00 / 5:00';
    $('#rec-lvl-fill').style.width='0%';
    try{
      var actx=new (window.AudioContext||window.webkitAudioContext)();
      var src=actx.createMediaStreamSource(stream);
      var an=actx.createAnalyser();an.fftSize=128;an.smoothingTimeConstant=.5;
      src.connect(an);
      var data=new Uint8Array(an.frequencyBinCount);
      r.sample=function(){
        an.getByteFrequencyData(data);
        var s=0;for(var i=0;i<data.length;i++)s+=data[i];
        return s/data.length;
      };
      r.stopAna=function(){try{src.disconnect();actx.close()}catch(e){}};
    }catch(e){
      r.sample=function(){return Math.random()*40};
      r.stopAna=function(){};
    }
    tickRec();
  }).catch(function(){
    alert('Нет доступа к микрофону. Разрешите доступ в настройках браузера и попробуйте ещё раз');
  });
}
function tickRec(){
  var r=S.rec;
  if(!r)return;
  var sec=Math.floor((Date.now()-r.start)/1000);
  if(sec>=300){stopRec();return}
  var lvl=r.sample?r.sample():0;
  r.wave.push(Math.min(255,Math.round(lvl*3)));
  if(r.wave.length>100)r.wave.shift();
  $('#rec-time').textContent=fmtDur(sec)+' / 5:00';
  $('#rec-lvl-fill').style.width=Math.min(100,Math.round(lvl)).toString()+'%';
  r.timer=setTimeout(tickRec,250);
}
function stopRec(){
  var r=S.rec;
  if(!r)return;
  S.rec=null;
  clearTimeout(r.timer);
  try{r.rec.stop()}catch(e){onRecStop(r)}
}
function cancelRec(){
  var r=S.rec;
  if(!r)return;
  S.rec=null;
  clearTimeout(r.timer);
  r.cancel=true;
  try{r.rec.onstop=null;r.rec.stop()}catch(e){}
  try{r.stream.getTracks().forEach(function(t){t.stop()})}catch(e){}
  if(r.stopAna)r.stopAna();
  $('#rec-bar').style.display='none';
}
function onRecStop(r){
  try{r.stream.getTracks().forEach(function(t){t.stop()})}catch(e){}
  if(r.stopAna)r.stopAna();
  $('#rec-bar').style.display='none';
  if(r.cancel)return;
  var blob=new Blob(r.chunks,{type:'audio/webm'});
  if(!blob.size){alert('Не удалось записать аудио');return}
  if(blob.size>10*1024*1024){alert('Запись слишком большая (больше 10 МБ)');return}
  var dur=Math.round((Date.now()-r.start)/1000);
  var fd=new FormData();
  fd.append('file',blob,'voice.webm');
  var btn=$('#btn-send');if(btn)btn.disabled=true;
  api('/api/upload',{method:'POST',body:fd}).then(function(d){
    if(btn)btn.disabled=false;
    sendMessage('',null,{url:d.url,duration:dur,wave:r.wave});
  }).catch(function(e){
    if(btn)btn.disabled=false;
    alert('Не удалось отправить голосовое: '+e.message+' — можно записать ещё раз');
  });
}
$('#btn-mic').onclick=function(){
  if(S.rec)stopRec();else startRec();
};
$('#rec-cancel').onclick=cancelRec;

/* ==== удаление сообщений ==== */
function delMessage(m){
  if(!confirm('Удалить сообщение?'))return;
  api('/api/chats/'+m.chatId+'/messages/'+m.id,{method:'DELETE'})
    .then(function(){m.deleted=true;updateMsgDom(m)})
    .catch(function(e){alert(e.message)});
}
function updateMsgDom(m){
  var el=document.querySelector('.msg[data-id="'+m.id+'"]');
  if(!el)return;
  var bubble=el.querySelector('.bubble');
  if(bubble){
    bubble.innerHTML='';
    bubble.className='bubble del';
    bubble.appendChild(h('div',{class:'b-text',text:'Сообщение удалено'}));
    bubble.appendChild(h('div',{class:'b-meta'},[document.createTextNode(fmtTime(m.createdAt))]));
  }
}

/* ==== состояние ввода: блокировки, каналы, запись ==== */
function updateInputState(){
  var chat=S.chats.find(function(c){return c.id===S.chatId});
  var ta=$('#ta'),mic=$('#btn-mic'),att=$('#btn-attach'),send=$('#btn-send'),bar=$('#chat-input'),banner=$('#blocked-banner');
  if(!chat)return;
  var canPost=chat.canPost!==false;
  if(chat.blocked){
    bar.style.display='none';
    banner.style.display='block';
    banner.textContent=chat.blocked==='me'
      ?'Вы заблокировали этого пользователя — чтобы писать, разблокируйте его (в его карточке)'
      :'Этот пользователь заблокировал вас — вы не можете отправлять сообщения';
    return;
  }
  bar.style.display='';
  banner.style.display='none';
  ta.disabled=!canPost;
  mic.style.display=canPost?'':'none';
  att.style.display=canPost?'':'none';
  send.disabled=!canPost;
  ta.placeholder=canPost?'Сообщение…':'Только администраторы канала могут писать';
}

/* ==== ссылки (?join=@канал, ?user=id) ==== */
function handleDeepLink(){
  try{
    var sp=new URLSearchParams(location.search);
    var join=sp.get('join');
    var user=sp.get('user');
    if(join){
      history.replaceState(null,'',location.pathname);
      api('/api/chats/by-handle?h='+encodeURIComponent(join))
        .then(function(c){openChannelInvite(c)})
        .catch(function(e){alert(e.message)});
    }else if(user){
      history.replaceState(null,'',location.pathname);
      api('/api/users/find?q='+encodeURIComponent(user))
        .then(function(d){openUserCard(d.user)})
        .catch(function(e){alert(e.message)});
    }
  }catch(e){}
}

/* ==== модалки ==== */
function overlay(content){
  var ov=h('div',{class:'overlay',onclick:function(ev){if(ev.target===ov)closeOverlay(ov)}},[content]);
  document.body.appendChild(ov);
  return ov;
}
function closeOverlay(ov){if(ov&&ov.parentNode)ov.parentNode.removeChild(ov)}
function modal(title,bodyEl,onClose){
  var ov=overlay(h('div',{class:'modal'},[
    h('div',{class:'modal-head'},[h('div',{class:'grow',text:title}),h('button',{class:'icon-btn',text:'✕',onclick:function(){closeOverlay(ov)}})]),
    h('div',{class:'modal-body'},[bodyEl].filter(Boolean))
  ]));
  return ov;
}

function openProfile(){
  var b=h('div',{},[]);
  b.appendChild(h('div',{class:'pf-row'},[
    h('div',{id:'pf-av-wrap'},[avatarEl(S.me,'lg')]),
    h('div',{class:'pf-info'},[
      h('div',{style:'font-weight:700;font-size:17px',text:S.me.displayName||S.me.username}),
      h('div',{class:'pf-username',text:'@'+S.me.username}),
      h('div',{class:'pf-spec',text:'Пользователь #'+S.me.id+(S.me.createdAt?(' · в Lowkey с '+fmtDate(S.me.createdAt)):'')})
    ])
  ]));
  b.appendChild(h('button',{class:'btn btn-ghost',style:'width:100%',onclick:function(){
    $('#file-avatar').click();
  }},[h('span',{text:'Сменить фото'})]));
  b.appendChild(h('button',{class:'btn btn-ghost',style:'width:100%',onclick:function(){
    api('/api/me/avatar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({clear:true})})
      .then(function(d){S.me=d.user;refreshFace()}).catch(function(e){alert(e.message)});
  }},{text:'Удалить фото'}));
  b.appendChild(h('input',{id:'file-avatar',type:'file',accept:'image/*',style:'display:none',onchange:function(){
    var f=this.files&&this.files[0];if(!f)return;
    var fd=new FormData();fd.append('file',f);
    api('/api/me/avatar',{method:'POST',body:fd}).then(function(d){
      S.me=d.user;refreshFace();
    }).catch(function(e){alert(e.message)});
  }}));
  b.appendChild(h('label',{class:'lbl',text:'Имя'}));
  b.appendChild(h('div',{class:'field'},[h('input',{id:'pf-name',value:S.me.displayName||''})]));
  b.appendChild(h('label',{class:'lbl',text:'Username (@)'}));
  b.appendChild(h('div',{class:'field'},[h('input',{id:'pf-username',value:S.me.username||''})]));
  b.appendChild(h('label',{class:'lbl',text:'О себе (до 200 символов)'}));
  b.appendChild(h('div',{class:'field'},[h('input',{id:'pf-bio',value:S.me.bio||'',placeholder:'Пара слов о себе'})]));
  b.appendChild(h('button',{class:'btn btn-primary',style:'margin-top:8px',onclick:function(){
    api('/api/me',{method:'PATCH',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:$('#pf-username').value.trim(),displayName:$('#pf-name').value.trim(),bio:$('#pf-bio').value})})
      .then(function(d){S.me=d.user;refreshFace();renderSidebar();renderChatHead()})
      .catch(function(e){alert(e.message)});
  }},{text:'Сохранить'}));
  b.appendChild(h('div',{class:'divider'}));
  b.appendChild(h('label',{class:'lbl',text:'Заблокированные пользователи'}));
  b.appendChild(h('div',{id:'blk-list'},[]));
  b.appendChild(h('div',{class:'divider'}));
  b.appendChild(h('button',{class:'btn btn-danger',style:'width:100%',onclick:function(){closeOverlay(ov);logout()}},{text:'Выйти из аккаунта'}));
  var ov=modal('Мой профиль',b);
  loadBlockedList();
}
function refreshFace(){
  $('#sb-avatar-wrap').innerHTML='';$('#sb-avatar-wrap').appendChild(avatarEl(S.me,'xs'));
  var pw=$('#pf-av-wrap');
  if(pw){pw.innerHTML='';pw.appendChild(avatarEl(S.me,'lg'))}
  renderSidebar();
}
function loadBlockedList(){
  var w=$('#blk-list');
  if(!w)return;
  api('/api/me/blocked').then(function(list){
    w.innerHTML='';
    if(!list||!list.length){w.appendChild(h('div',{class:'sr-null',text:'У вас никого нет в списке заблокированных'}));return}
    list.forEach(function(u){
      w.appendChild(h('div',{class:'gm-item'},[
        avatarEl(u,'xs'),
        h('div',{class:'gm-name',text:u.displayName||u.username}),
        h('div',{class:'gm-un',text:'@'+u.username}),
        h('button',{class:'btn btn-ghost',style:'padding:6px 10px;font-size:12px',onclick:function(){
          api('/api/users/'+u.id+'/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({blocked:false})})
            .then(function(){loadBlockedList()}).catch(function(e){alert(e.message)});
        }},{text:'Разблокировать'})
      ]));
    });
  }).catch(function(e){alert(e.message)});
}

function fmtStatus(u){
  if(!u)return {text:'нет данных',cls:''};
  if(u.blocked)return {text:'заблокирован',cls:''};
  if(u.online)return {text:'онлайн',cls:'online'};
  var l=fmtLastSeen(u.lastSeen);
  if(l)return {text:l,cls:''};
  return {text:'не в сети',cls:''};
}
function openUserCard(u){
  var id=(u&&typeof u==='object')?u.id:Number(u);
  if(!id)return;
  api('/api/users/'+id).then(function(d){renderUserCard(d.user)}).catch(function(e){alert(e.message)});
}
function renderUserCard(u){
  var b=h('div',{},[]);
  var st=fmtStatus(u);
  b.appendChild(h('div',{class:'pf-row'},[
    h('div',{},[avatarEl(u,'lg')]),
    h('div',{class:'pf-info'},[
      h('div',{style:'font-weight:700;font-size:17px',text:u.displayName||u.username}),
      h('div',{class:'pf-username',text:'@'+u.username}),
      h('div',{class:'ch-status'+(st.cls?(' '+st.cls):''),text:st.text})
    ])
  ]));
  if(u.blocked)b.appendChild(h('div',{class:'pf-spec',text:'⚠ Пользователь заблокирован администратором'}));
  b.appendChild(h('div',{class:'pf-spec',text:'Пользователь #'+u.id}));
  if(u.createdAt)b.appendChild(h('div',{class:'pf-spec',text:'В Lowkey с '+fmtDate(u.createdAt)}));
  if(u.bio)b.appendChild(h('div',{style:'font-size:14px;line-height:1.5;margin-top:10px',text:u.bio}));
  if(u.youBlocked||u.blockedYou){
    b.appendChild(h('div',{class:'blocked-banner',style:'display:block;margin:10px 0',text:u.youBlocked?'Вы заблокировали этого пользователя':'Этот пользователь заблокировал вас'}));
  }
  b.appendChild(h('div',{class:'divider'}));
  b.appendChild(h('button',{class:'btn btn-primary',style:'width:100%',onclick:function(){
    closeOverlay(ov);openPrivate(u.id);
  }},{text:'Написать сообщение'}));
  b.appendChild(h('button',{class:'btn btn-ghost',style:'width:100%',onclick:function(){
    copyText(location.origin+(location.pathname||'/')+'?user='+u.id);
  }},{text:'🔗 Поделиться профилем'}));
  if(u.id!==S.me.id){
    b.appendChild(h('button',{class:'btn btn-ghost',style:'width:100%;color:var(--danger)',onclick:function(){
      api('/api/users/'+u.id+'/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({blocked:!u.youBlocked})})
        .then(function(){closeOverlay(ov);openUserCard(u.id)})
        .catch(function(e){alert(e.message)});
    }},{text:u.youBlocked?'Разблокировать':'Заблокировать'}));
  }
  var ov=modal('Профиль',b);
}

function openGroupCreate(){
  var selected=[];
  var listWrap=h('div',{},[]);
  var b=h('div',{},[]);
  b.appendChild(h('label',{class:'lbl',text:'Название группы'}));
  b.appendChild(h('div',{class:'field'},[h('input',{id:'gm-name',placeholder:'Например: Проект или Друзья'})]));
  b.appendChild(h('label',{class:'lbl',text:'Участники (поиск по username)'}));
  b.appendChild(h('div',{class:'field'},[h('input',{id:'gm-search',placeholder:'Введите username…'})]));
  b.appendChild(listWrap);
  b.appendChild(h('button',{class:'btn btn-primary',style:'margin-top:10px',onclick:function(){
    var name=$('#gm-name').value.trim();
    if(!name){alert('Введите название группы');return}
    if(!selected.length){alert('Выберите хотя бы одного участника');return}
    api('/api/chats/group',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({name:name,memberIds:selected})})
      .then(function(c){closeOverlay(ov);upsertChat(c);selectChat(c.id)})
      .catch(function(e){alert(e.message)});
  }},{text:'Создать группу'}));
  var ov=modal('Новая группа',b);
  $('#gm-search').addEventListener('input',function(){
    var q=this.value.trim();
    if(!q){listWrap.innerHTML='';return}
    api('/api/users/search?q='+encodeURIComponent(q)).then(function(list){
      listWrap.innerHTML='';
      list.forEach(function(u){
        var cb=h('input',{type:'checkbox',id:'gm-cb-'+u.id});
        cb.checked=selected.indexOf(u.id)>=0;
        cb.onchange=function(){
          var i=selected.indexOf(u.id);
          if(cb.checked&&i<0)selected.push(u.id);
          if(!cb.checked&&i>=0)selected.splice(i,1);
        };
        listWrap.appendChild(h('label',{class:'gm-item'},[
          cb,
          avatarEl(u,'xs'),
          h('div',{class:'gm-name',text:u.displayName||u.username}),
          h('div',{class:'gm-un',text:'@'+u.username})
        ]));
      });
    }).catch(function(){});
  });
}

function openGroupInfo(chat){
  var b=h('div',{},[]);
  if(chat.type==='channel'){
    b.appendChild(h('div',{class:'pf-row'},[
      h('div',{},[avatarEl({id:chat.id,displayName:chat.name,avatar:chat.avatar},'lg')]),
      h('div',{class:'pf-info'},[
        h('div',{style:'font-weight:700;font-size:17px',text:chat.name}),
        h('div',{class:'pf-username',text:'#'+chat.handle}),
        h('div',{class:'ch-status',text:(chat.visibility==='private'?'Приватный канал':'Публичный канал')+' · '+(chat.members?chat.members.length:0)+' подписчиков'})
      ])
    ]));
    if(chat.description)b.appendChild(h('div',{style:'font-size:14px;line-height:1.5;margin-top:10px',text:chat.description}));
    b.appendChild(h('button',{class:'btn btn-ghost',style:'width:100%',onclick:function(){
      copyText(inviteLinkFor(chat));
    }},{text:'🔗 Скопировать ссылку-приглашение'}));
    if((chat.admins||[]).indexOf(S.me.id)>=0){
      b.appendChild(h('button',{class:'btn btn-ghost',style:'width:100%',onclick:function(){addChatMembers(chat)}},{text:'➕ Пригласить подписчика'}));
    }
    b.appendChild(h('div',{class:'divider'}));
    b.appendChild(h('button',{class:'btn btn-ghost',style:'width:100%;color:var(--danger)',onclick:function(){closeOverlay(ov);clearHistory(chat.id)}},{text:'🧹 Очистить историю'}));
    b.appendChild(h('button',{class:'btn btn-ghost',style:'width:100%',onclick:function(){closeOverlay(ov);leaveChat(chat.id)}},{text:'👋 Отписаться от канала'}));
  }else{
    b.appendChild(h('div',{class:'pf-row'},[
      h('div',{},[avatarEl({id:chat.id,displayName:chat.name,avatar:chat.avatar},'lg')]),
      h('div',{class:'pf-info'},[
        h('div',{style:'font-weight:700;font-size:17px',text:chat.name}),
        h('div',{class:'pf-username',text:'Группа · '+(chat.members?chat.members.length:0)+' участников'})
      ])
    ]));
    b.appendChild(h('div',{class:'divider'}));
    (chat.members||[]).forEach(function(u){
      b.appendChild(h('div',{class:'gm-item',onclick:function(){openUserCard(u)}},[
        avatarEl(u,'xs'),
        h('div',{class:'gm-name',text:u.displayName||u.username}),
        u.online?h('span',{class:'ch-status online',text:'онлайн'}):null
      ]));
    });
    b.appendChild(h('button',{class:'btn btn-ghost',style:'width:100%',onclick:function(){addChatMembers(chat)}},{text:'➕ Пригласить участника'}));
    b.appendChild(h('button',{class:'btn btn-ghost',style:'width:100%;color:var(--danger)',onclick:function(){closeOverlay(ov);clearHistory(chat.id)}},{text:'🧹 Очистить историю'}));
    b.appendChild(h('button',{class:'btn btn-ghost',style:'width:100%',onclick:function(){closeOverlay(ov);leaveChat(chat.id)}},{text:'👋 Покинуть группу'}));
  }
  var ov=modal('Информация',b);
}

/* ==== админ-панель ==== */
function openAdminPanel(){
  var listWrap=h('div',{},[]);
  var statsEl=h('div',{class:'pf-username',style:'margin-top:4px;margin-bottom:8px',text:'Загрузка…'});
  var regRow=h('label',{class:'gm-item'},[
    h('input',{type:'checkbox',id:'adm-reg'}),
    h('div',{class:'gm-name',text:'Разрешить регистрацию новых пользователей'})
  ]);
  var state={q:'',perPage:20,page:1,sort:'newest',status:'all',total:0,pages:1};
  var b=h('div',{},[]);
  b.appendChild(regRow);
  b.appendChild(statsEl);
  b.appendChild(h('div',{class:'divider'}));
  b.appendChild(h('label',{class:'lbl',text:'Пользователи'}));
  b.appendChild(h('div',{class:'field'},[h('input',{id:'adm-search',placeholder:'Имя, @username или ID'})]));
  b.appendChild(h('div',{class:'adm-ctrl'},[
    h('select',{id:'adm-per'},[
      h('option',{value:'20',text:'20 на стр.'}),
      h('option',{value:'50',text:'50 на стр.'}),
      h('option',{value:'100',text:'100 на стр.'})
    ]),
    h('select',{id:'adm-sort'},[
      h('option',{value:'newest',text:'Сначала новые'}),
      h('option',{value:'oldest',text:'Сначала старые'}),
      h('option',{value:'id',text:'По ID'}),
      h('option',{value:'name',text:'По имени'})
    ]),
    h('select',{id:'adm-status'},[
      h('option',{value:'all',text:'Все статусы'}),
      h('option',{value:'online',text:'Только онлайн'}),
      h('option',{value:'offline',text:'Не в сети'}),
      h('option',{value:'banned',text:'Заблокированы'})
    ])
  ]));
  b.appendChild(listWrap);
  b.appendChild(h('div',{class:'adn'},[
    h('button',{class:'btn btn-ghost adm-prev',text:'← Назад'}),
    h('div',{class:'adm-page'}),
    h('button',{class:'btn btn-ghost adm-next',text:'Вперёд →'})
  ]));
  var ov=modal('Админ-панель',b);
  var pageEl=ov.querySelector('.adm-page');
  var prevBtnEl=ov.querySelector('.adm-prev');
  var nextBtnEl=ov.querySelector('.adm-next');

  function refresh(){
    api('/api/admin/users?q='+encodeURIComponent(state.q)+'&perPage='+state.perPage+'&page='+state.page+'&sort='+state.sort)
      .then(function(d){
        state.total=d.total;state.pages=d.pages;state.page=d.page;
        var list=d.users;
        if(state.status==='online')list=list.filter(function(u){return !u.blocked&&u.online});
        else if(state.status==='offline')list=list.filter(function(u){return !u.blocked&&!u.online});
        else if(state.status==='banned')list=list.filter(function(u){return u.blocked});
        listWrap.innerHTML='';
        if(!list.length)listWrap.appendChild(h('div',{class:'sr-null',text:'Ничего не найдено'}));
        list.forEach(function(u){listWrap.appendChild(admUserRow(u,refresh))});
        pageEl.textContent='стр. '+d.page+' из '+d.pages+' · всего '+d.total;
        prevBtnEl.disabled=d.page<=1;
        nextBtnEl.disabled=d.page>=d.pages;
      }).catch(function(e){
        listWrap.innerHTML='';
        listWrap.appendChild(h('div',{class:'sr-null',text:'Ошибка: '+e.message}));
      });
  }
  function loadStats(){
    api('/api/admin/stats').then(function(st){
      statsEl.textContent=st.users+' пользователей · '+st.chats+' чатов · '+st.messages+' сообщений';
      if(!st.users)statsEl.textContent='Пока нет пользователей';
    }).catch(function(){});
  }
  $('#adm-reg').onchange=function(){
    api('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({registrationOpen:$('#adm-reg').checked})}).catch(function(e){alert(e.message)});
  };
  var admTimer;
  $('#adm-search').addEventListener('input',function(){
    var self=this;
    clearTimeout(admTimer);
    admTimer=setTimeout(function(){state.q=self.value.trim();state.page=1;refresh()},250);
  });
  $('#adm-per').onchange=function(){state.perPage=Number(this.value);state.page=1;refresh()};
  $('#adm-sort').onchange=function(){state.sort=this.value;state.page=1;refresh()};
  $('#adm-status').onchange=function(){state.status=this.value;refresh()};
  if(prevBtnEl)prevBtnEl.onclick=function(){if(state.page>1){state.page--;refresh()}};
  if(nextBtnEl)nextBtnEl.onclick=function(){if(state.page<state.pages){state.page++;refresh()}};

  api('/api/admin/settings').then(function(s){$('#adm-reg').checked=!!s.registrationOpen}).catch(function(){});
  loadStats();
  refresh();
}
function admUserRow(u,reload){
  var st=fmtStatus(u);
  var meta=u.blocked?' · заблокирован админом':(u.role==='admin'?' · админ':'');
  var row=h('div',{class:'gm-item'},[
    avatarEl(u,'xs'),
    h('div',{class:'gm-name'},[
      h('div',{text:u.displayName||u.username}),
      h('div',{class:'gm-un',text:'@'+u.username+' · ID '+u.id+meta})
    ]),
    h('span',{class:'ch-status'+(st.cls?(' '+st.cls):''),text:st.text}),
    u.id!==S.me.id&&u.role!=='admin'
      ?h('button',{class:'btn btn-ghost',style:'padding:6px 10px;font-size:12px',onclick:function(){
          api('/api/admin/users/'+u.id+'/block',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({blocked:!u.blocked})}).then(reload).catch(function(e){alert(e.message)});
        }},{text:u.blocked?'Разблокировать':'Заблокировать'})
      :null,
    u.id!==S.me.id
      ?h('button',{class:'btn btn-ghost',style:'padding:6px 10px;font-size:12px',onclick:function(){
          api('/api/admin/users/'+u.id+'/role',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({role:u.role==='admin'?'user':'admin'})}).then(reload).catch(function(e){alert(e.message)});
        }},{text:u.role==='admin'?'Убрать админа':'Сделать админом'})
      :null,
    h('button',{class:'btn btn-ghost',style:'padding:6px 10px;font-size:12px',onclick:function(){openUserCard(u.id)}},{text:'👁 Карточка'})
  ]);
  return row;
}

/* ==== старт ==== */
function boot(){
  if(S.token){
    api('/api/me').then(function(d){
      S.me=d.user;
      showApp();
      connectWs();
    }).catch(function(){S.token='';localStorage.removeItem('lowkey_token');showAuth()});
  }else showAuth();
}
boot();
</script>
</body>
</html>`;

app.get('/', (req, res) => res.type('html').send(INDEX_HTML));

/* ============================================================================
   СТАРТ
============================================================================ */

server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  Lowkey мессенджер запущен');
  console.log('  Откройте в браузере: http://localhost:' + PORT);
  console.log('  Данные хранятся в: ' + DATA_DIR);
  console.log('');
});

process.on('SIGINT', () => {
  clearInterval(heartbeat);
  process.exit(0);
});