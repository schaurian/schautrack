const express = require('express');
const { pool } = require('../db/pool');
const { requireLogin } = require('../middleware/auth');
const { toInt } = require('../lib/utils');
const { countAcceptedLinks, getLinkBetween } = require('../lib/links');
const { broadcastLinkLabelChange } = require('./sse');

const router = express.Router();

const MAX_LINKS = 3;

function setLinkFeedback(req, type, message) {
  req.session.linkFeedback = { type, message };
}

router.post('/settings/link/request', requireLogin, async (req, res) => {
  const emailRaw = (req.body.email || '').trim();
  if (!emailRaw) {
    setLinkFeedback(req, 'error', 'Email is required.');
    return res.redirect('/settings');
  }

  try {
    const { rows } = await pool.query('SELECT id, email FROM users WHERE LOWER(email) = LOWER($1)', [
      emailRaw,
    ]);
    const target = rows[0];
    if (!target) {
      setLinkFeedback(req, 'error', 'No account found for that email.');
      return res.redirect('/settings');
    }
    const currentId = toInt(req.currentUser.id);
    const targetId = toInt(target.id);
    if (currentId === null || targetId === null) {
      setLinkFeedback(req, 'error', 'Could not send link request.');
      return res.redirect('/settings');
    }
    if (targetId === currentId) {
      setLinkFeedback(req, 'error', 'You cannot link to your own account.');
      return res.redirect('/settings');
    }

    const existing = await getLinkBetween(currentId, targetId);
    if (existing) {
      if (existing.status === 'accepted') {
        setLinkFeedback(req, 'error', 'You are already linked with this account.');
      } else if (existing.requester_id === req.currentUser.id) {
        setLinkFeedback(req, 'error', 'Request already sent and pending approval.');
      } else {
        setLinkFeedback(req, 'error', 'They already sent you a request. Check incoming requests below.');
      }
      return res.redirect('/settings');
    }

    const myAccepted = await countAcceptedLinks(currentId);
    if (myAccepted >= MAX_LINKS) {
      setLinkFeedback(req, 'error', `You already have ${MAX_LINKS} linked accounts.`);
      return res.redirect('/settings');
    }

    const targetAccepted = await countAcceptedLinks(targetId);
    if (targetAccepted >= MAX_LINKS) {
      setLinkFeedback(req, 'error', 'The other account already reached the linking limit.');
      return res.redirect('/settings');
    }

    await pool.query('INSERT INTO account_links (requester_id, target_id, status) VALUES ($1, $2, $3)', [
      currentId,
      targetId,
      'pending',
    ]);
    setLinkFeedback(req, 'success', `Request sent to ${target.email}.`);
  } catch (err) {
    console.error('Link request error', err);
    setLinkFeedback(req, 'error', 'Could not send link request.');
  }

  return res.redirect('/settings');
});

router.post('/settings/link/respond', requireLogin, async (req, res) => {
  const requestId = parseInt(req.body.request_id, 10);
  const action = (req.body.action || '').trim();
  if (Number.isNaN(requestId) || !['accept', 'decline'].includes(action)) {
    return res.redirect('/settings');
  }

  try {
    const currentId = toInt(req.currentUser.id);
    if (currentId === null) {
      setLinkFeedback(req, 'error', 'Could not update request.');
      return res.redirect('/settings');
    }
    const { rows } = await pool.query(
      'SELECT * FROM account_links WHERE id = $1 AND status = $2 LIMIT 1',
      [requestId, 'pending']
    );
    const request = rows[0];
    if (!request || request.target_id !== currentId) {
      setLinkFeedback(req, 'error', 'Request not found.');
      return res.redirect('/settings');
    }

    if (action === 'accept') {
      const myAccepted = await countAcceptedLinks(currentId);
      if (myAccepted >= MAX_LINKS) {
        setLinkFeedback(req, 'error', `You already have ${MAX_LINKS} linked accounts.`);
        return res.redirect('/settings');
      }
      const requesterAccepted = await countAcceptedLinks(request.requester_id);
      if (requesterAccepted >= MAX_LINKS) {
        setLinkFeedback(req, 'error', 'The requester is already at the link limit.');
        return res.redirect('/settings');
      }

      await pool.query('UPDATE account_links SET status = $1, updated_at = NOW() WHERE id = $2', [
        'accepted',
        requestId,
      ]);
      setLinkFeedback(req, 'success', 'Link request accepted.');
    } else {
      await pool.query('DELETE FROM account_links WHERE id = $1 AND target_id = $2', [
        requestId,
        req.currentUser.id,
      ]);
      setLinkFeedback(req, 'success', 'Request declined.');
    }
  } catch (err) {
    console.error('Link respond error', err);
    setLinkFeedback(req, 'error', 'Could not update request.');
  }

  return res.redirect('/settings');
});

router.post('/settings/link/remove', requireLogin, async (req, res) => {
  const linkId = parseInt(req.body.link_id, 10);
  if (Number.isNaN(linkId)) {
    return res.redirect('/settings');
  }

  try {
    const currentId = toInt(req.currentUser.id);
    if (currentId === null) {
      setLinkFeedback(req, 'error', 'Could not update link.');
      return res.redirect('/settings');
    }
    const { rows } = await pool.query(
      'DELETE FROM account_links WHERE id = $1 AND (requester_id = $2 OR target_id = $2) RETURNING status',
      [linkId, currentId]
    );
    if (rows.length === 0) {
      setLinkFeedback(req, 'error', 'Link not found.');
    } else if (rows[0].status === 'accepted') {
      setLinkFeedback(req, 'success', 'Link removed.');
    } else {
      setLinkFeedback(req, 'success', 'Request cancelled.');
    }
  } catch (err) {
    console.error('Link remove error', err);
    setLinkFeedback(req, 'error', 'Could not update link.');
  }

  return res.redirect('/settings');
});

router.post('/links/:id/label', requireLogin, async (req, res) => {
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