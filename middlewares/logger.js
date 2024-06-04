const logger = (req, res, next) => {
    // Log request body for POST requests
    if (req.method === 'POST') {
    }
    next();
};

module.exports = logger;