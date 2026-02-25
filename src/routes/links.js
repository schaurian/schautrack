const express = require('express');
const { pool } = require('../db/pool');
const { requireLogin } = require('../middleware/auth');
const { csrfProtection } = require('../middleware/csrf');
const { toInt } = require('../lib/utils');
const { countAcceptedLinks, getLinkBetween, countAcceptedLinksWithClient } = require('../lib/links');
const { broadcastLinkLabelChange, broadcastLinkChange } = require('./sse');

const router = express.Router();

const MAX_LINKS = 3;

function setLinkFeedback(req, type, message) {
  req.session.linkFeedback = { type, message };
}

function wantsJson(req) {
  return (req.headers.accept || '').includes('application/json');
}

function jsonOrRedirect(req, res, status, message, httpCode) {
  if (wantsJson(req)) {
    const code = status === 'error' ? (httpCode || 400) : 200;
    return res.status(code).json({ ok: status !== 'error', message });
  }
  setLinkFeedback(req, status, message);
  return res.redirect('/settings');
}

router.post('/settings/link/request', requireLogin, csrfProtection, async (req, res) => {
  const emailRaw = (req.body.email || '').trim();
  if (!emailRaw) {
    return jsonOrRedirect(req, res, 'error', 'Email is required.');
  }

  try {
    const { rows } = await pool.query('SELECT id, email FROM users WHERE LOWER(email) = LOWER($1)', [
      emailRaw,
    ]);
    const target = rows[0];
    if (!target) {
      return jsonOrRedirect(req, res, 'error', 'No account found for that email.', 404);
    }
    const currentId = toInt(req.currentUser.id);
    const targetId = toInt(target.id);
    if (currentId === null || targetId === null) {
      return jsonOrRedirect(req, res, 'error', 'Could not send link request.', 500);
    }
    if (targetId === currentId) {
      return jsonOrRedirect(req, res, 'error', 'You cannot link to your own account.');
    }

    const existing = await getLinkBetween(currentId, targetId);
    if (existing) {
      if (existing.status === 'accepted') {
        return jsonOrRedirect(req, res, 'error', 'You are already linked with this account.', 409);
      } else if (existing.requester_id === req.currentUser.id) {
        return jsonOrRedirect(req, res, 'error', 'Request already sent and pending approval.', 409);
      } else {
        return jsonOrRedirect(req, res, 'error', 'They already sent you a request. Check incoming requests below.', 409);
      }
    }

    const myAccepted = await countAcceptedLinks(currentId);
    if (myAccepted >= MAX_LINKS) {
      return jsonOrRedirect(req, res, 'error', `You already have ${MAX_LINKS} linked accounts.`, 409);
    }

    const targetAccepted = await countAcceptedLinks(targetId);
    if (targetAccepted >= MAX_LINKS) {
      return jsonOrRedirect(req, res, 'error', 'The other account already reached the linking limit.', 409);
    }

    const { rows: inserted } = await pool.query(
      'INSERT INTO account_links (requester_id, target_id, status) VALUES ($1, $2, $3) RETURNING id, created_at',
      [currentId, targetId, 'pending']
    );
    broadcastLinkChange(targetId, 'request', {
      requestId: inserted[0].id,
      email: req.currentUser.email,
      created_at: inserted[0].created_at,
    });
    if (wantsJson(req)) {
      return res.json({
        ok: true,
        message: `Request sent to ${target.email}.`,
        request: { id: inserted[0].id, email: target.email, created_at: inserted[0].created_at }
      });
    }
    setLinkFeedback(req, 'success', `Request sent to ${target.email}.`);
  } catch (err) {
    console.error('Link request error', err);
    return jsonOrRedirect(req, res, 'error', 'Could not send link request.', 500);
  }

  return res.redirect('/settings');
});

router.post('/settings/link/respond', requireLogin, csrfProtection, async (req, res) => {
  const requestId = parseInt(req.body.request_id, 10);
  const action = (req.body.action || '').trim();
  if (Number.isNaN(requestId) || !['accept', 'decline'].includes(action)) {
    return jsonOrRedirect(req, res, 'error', 'Invalid request.');
  }

  try {
    const currentId = toInt(req.currentUser.id);
    if (currentId === null) {
      return jsonOrRedirect(req, res, 'error', 'Could not update request.', 500);
    }
    const { rows } = await pool.query(
      'SELECT * FROM account_links WHERE id = $1 AND status = $2 LIMIT 1',
      [requestId, 'pending']
    );
    const request = rows[0];
    if (!request || request.target_id !== currentId) {
      return jsonOrRedirect(req, res, 'error', 'Request not found.', 404);
    }

    if (action === 'accept') {
      const client = await pool.connect();
      try {
        await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
        const myAccepted = await countAcceptedLinksWithClient(client, currentId);
        if (myAccepted >= MAX_LINKS) {
          await client.query('ROLLBACK');
          return jsonOrRedirect(req, res, 'error', `You already have ${MAX_LINKS} linked accounts.`, 409);
        }
        const requesterAccepted = await countAcceptedLinksWithClient(client, request.requester_id);
        if (requesterAccepted >= MAX_LINKS) {
          await client.query('ROLLBACK');
          return jsonOrRedirect(req, res, 'error', 'The requester is already at the link limit.', 409);
        }

        await client.query('UPDATE account_links SET status = $1, updated_at = NOW() WHERE id = $2', [
          'accepted',
          requestId,
        ]);
        await client.query('COMMIT');
      } catch (txErr) {
        await client.query('ROLLBACK');
        throw txErr;
      } finally {
        client.release();
      }
      broadcastLinkChange(request.requester_id, 'accepted', {
        linkId: requestId,
        userId: currentId,
        email: req.currentUser.email,
      });
      return jsonOrRedirect(req, res, 'success', 'Link request accepted.');
    } else {
      await pool.query('DELETE FROM account_links WHERE id = $1 AND target_id = $2', [
        requestId,
        req.currentUser.id,
      ]);
      broadcastLinkChange(request.requester_id, 'declined', {
        requestId,
        email: req.currentUser.email,
      });
      return jsonOrRedirect(req, res, 'success', 'Request declined.');
    }
  } catch (err) {
    console.error('Link respond error', err);
    return jsonOrRedirect(req, res, 'error', 'Could not update request.', 500);
  }
});

router.post('/settings/link/remove', requireLogin, csrfProtection, async (req, res) => {
  const linkId = parseInt(req.body.link_id, 10);
  if (Number.isNaN(linkId)) {
    return jsonOrRedirect(req, res, 'error', 'Invalid link.');
  }

  try {
    const currentId = toInt(req.currentUser.id);
    if (currentId === null) {
      return jsonOrRedirect(req, res, 'error', 'Could not update link.', 500);
    }
    const { rows } = await pool.query(
      'DELETE FROM account_links WHERE id = $1 AND (requester_id = $2 OR target_id = $2) RETURNING status, requester_id, target_id',
      [linkId, currentId]
    );
    if (rows.length === 0) {
      return jsonOrRedirect(req, res, 'error', 'Link not found.', 404);
    }
    const deleted = rows[0];
    const otherId = deleted.requester_id === currentId ? deleted.target_id : deleted.requester_id;
    if (deleted.status === 'accepted') {
      broadcastLinkChange(otherId, 'removed', { linkId });
      return jsonOrRedirect(req, res, 'success', 'Link removed.');
    } else {
      broadcastLinkChange(otherId, 'cancelled', { requestId: linkId });
      return jsonOrRedirect(req, res, 'success', 'Request cancelled.');
    }
  } catch (err) {
    console.error('Link remove error', err);
    return jsonOrRedirect(req, res, 'error', 'Could not update link.', 500);
  }
});

router.post('/links/:id/label', requireLogin, csrfProtection, async (req, res) => {
  const linkId = toInt(req.params.id);
  if (linkId === null) {
    return res.status(400).json({ ok: false, error: 'Invalid link' });
  }
  const rawLabel = typeof req.body.label === 'string' ? req.body.label.trim() : '';
  const label = rawLabel ? rawLabel.slice(0, 120) : null;

  try {
    const { rows } = await pool.query(
      `UPDATE account_links
          SET requester_label = CASE WHEN requester_id = $3 THEN $1 ELSE requester_label END,
              target_label = CASE WHEN target_id = $3 THEN $1 ELSE target_label END,
              updated_at = NOW()
        WHERE id = $2
          AND status = 'accepted'
          AND ($3 = requester_id OR $3 = target_id)
        RETURNING id,
          CASE WHEN requester_id = $3 THEN requester_label ELSE target_label END AS label,
          $3::int AS actor_id`,
      [label, linkId, req.currentUser.id]
    );
    const updated = rows[0];
    if (!updated) {
      return res.status(404).json({ ok: false, error: 'Link not found' });
    }
    await broadcastLinkLabelChange(updated.id, updated.actor_id, updated.label);
    return res.json({ ok: true, label: updated.label || null });
  } catch (err) {
    console.error('Failed to update link label', err);
    return res.status(500).json({ ok: false, error: 'Could not update label' });
  }
});

module.exports = router;