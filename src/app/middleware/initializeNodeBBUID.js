/**
 * Middleware to ensure NodeBB UID is initialized in session before write operations
 */

const request = require('request');
const logger = require('sb_logger_util_v2');

function initializeNodeBBUID(discussions_middleware) {
    return async function(req, res, next) {
        // Skip if NodeBB UID already exists
        if (req.session['nodebb_uid']) {
            return next();
        }

        // Skip if no Sunbird user session
        if (!req.session.userId) {
            return next();
        }

        try {
            // Call user lookup API to get/create NodeBB UID
            const options = {
                url: `${discussions_middleware}/api/user/lookup`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': req.headers.authorization || `Bearer ${req.session.access_token}`
                },
                json: {
                    sunbird_uid: req.session.userId,
                    username: req.session.userName,
                    email: req.session.userEmail || `${req.session.userName}@sunbird.org`
                }
            };

            request(options, (error, response, body) => {
                if (!error && body && body.uid) {
                    req.session['nodebb_uid'] = body.uid;
                    logger.info('Initialized NodeBB UID:', body.uid, 'for Sunbird user:', req.session.userId);
                } else {
                    logger.warn('Failed to initialize NodeBB UID for user:', req.session.userId, error || body);
                }
                next();
            });
        } catch (error) {
            logger.error('Error initializing NodeBB UID:', error);
            next();
        }
    };
}

module.exports = initializeNodeBBUID;