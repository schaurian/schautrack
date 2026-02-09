const express = require('express');
const { requireLogin } = require('../middleware/auth');
const { toInt } = require('../lib/utils');

const router = express.Router();

const userEventClients = new Map(); // userId -> Set(res)

function addUserEventClient(userId, res) {
  if (!userEventClients.has(userId)) {
    userEventClients.set(userId, new Set());
  }
  userEventClients.get(userId).add(res);
}

function removeUserEventClient(userId, res) {
  const set = userEventClients.get(userId);
  if (!set) return;
  set.delete(res);
  if (set.size === 0) {
    userEventClients.delete(userId);
  }
}

function sendUserEvent(userId, eventName, payload) {
  const set = userEventClients.get(userId);
  if (!set || set.size === 0) return;
  const data = `event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`;
  const staleConnections = [];
  
  for (const res of set) {
    try {
      res.write(data);
    } catch (err) {
      // Connection is stale, mark for removal
      staleConnections.push(res);
    }
  }
  
  // Clean up stale connections
  for (const staleRes of staleConnections) {
    removeUserEventClient(userId, staleRes);
  }
}

async function broadcastLinkLabelChange(linkId, userId, label) {
  const lid = toInt(linkId);
  const uid = toInt(userId);
  if (lid === null || uid === null) return;
  const payload = { linkId: lid, label: label || null };
  sendUserEvent(uid, 'link-label-change', payload);
}

router.get('/events/entries', requireLogin, (req, res) => {
  const userId = toInt(req.currentUser?.id);
  if (userId === null) {
    return res.sendStatus(401);
  }
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  if (res.flushHeaders) res.flushHeaders();
  res.write('event: ready\ndata: {}\n\n');

  addUserEventClient(userId, res);
  const keepAlive = setInterval(() => {
    res.write('event: ping\ndata: {}\n\n');
  }, 25000);

  req.on('close', () => {
    clearInterval(keepAlive);
    removeUserEventClient(userId, res);
    res.end();
  });
});

// Periodic cleanup for stale SSE connections
setInterval(() => {
  for (const [userId, resSet] of userEventClients.entries()) {
    const staleConnections = [];
    
    for (const res of resSet) {
      try {
        // Test connection by writing a ping
        res.write('event: cleanup-ping\ndata: {}\n\n');
      } catch (err) {
        // Connection is stale
        staleConnections.push(res);
      }
    }
    
    // Remove stale connections
    for (const staleRes of staleConnections) {
      removeUserEventClient(userId, staleRes);
    }
  }
}, 5 * 60 * 1000); // Run every 5 minutes

module.exports = {
  router,
  sendUserEvent,
  broadcastLinkLabelChange
};