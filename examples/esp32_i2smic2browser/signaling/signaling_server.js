const http = require('http');
const WebSocket = require('ws');

const PORT = 8000;

const server = http.createServer();
const wss = new WebSocket.Server({ server });
const rooms = new Map();

function getPath(req) {
  if (!req || !req.url) {
    return '/';
  }
  return req.url;
}

function getRoom(pathname) {
  let room = rooms.get(pathname);
  if (!room) {
    room = new Set();
    rooms.set(pathname, room);
  }
  return room;
}

function removeClient(pathname, ws) {
  const room = rooms.get(pathname);
  if (!room) {
    return;
  }
  room.delete(ws);
  if (room.size === 0) {
    rooms.delete(pathname);
  }
}

wss.on('connection', (ws, req) => {
  const pathname = getPath(req);
  const room = getRoom(pathname);

  room.add(ws);
  console.log(`connected path=${pathname} clients=${room.size}`);

  ws.on('message', (message, isBinary) => {
    const text = isBinary ? '<binary>' : message.toString();
    console.log(`message path=${pathname} bytes=${message.length} payload=${text}`);

    let forwarded = 0;
    for (const client of room) {
      if (client === ws || client.readyState !== WebSocket.OPEN) {
        continue;
      }
      client.send(message, { binary: isBinary });
      forwarded += 1;
    }
    console.log(`forwarded path=${pathname} recipients=${forwarded}`);
  });

  ws.on('close', () => {
    removeClient(pathname, ws);
    const remaining = rooms.get(pathname)?.size ?? 0;
    console.log(`disconnected path=${pathname} clients=${remaining}`);
  });

  ws.on('error', (err) => {
    console.error(`socket error path=${pathname}:`, err.message);
  });
});

server.listen(PORT, () => {
  console.log(`signaling server listening on ws://0.0.0.0:${PORT}`);
});
