// Centralized error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  // Don't crash on errors, just log and respond appropriately
  const wantsJson = req.headers.accept && req.headers.accept.includes('application/json');
  
  if (wantsJson) {
    return res.status(500).json({ 
      ok: false, 
      error: 'Internal server error'
    });
  }
  
  // For web pages, redirect to dashboard or login
  if (req.currentUser) {
    return res.redirect('/dashboard');
  } else {
    return res.redirect('/login');
  }
};

// 404 handler for unmatched routes
const notFoundHandler = (req, res) => {
  const wantsJson = req.headers.accept && req.headers.accept.includes('application/json');
  
  if (wantsJson) {
    return res.status(404).json({ 
      ok: false, 
      error: 'Not found'
    });
  }
  
  if (req.currentUser) {
    return res.redirect('/dashboard');
  } else {
    return res.redirect('/');
  }
};

module.exports = {
  errorHandler,
  notFoundHandler
};