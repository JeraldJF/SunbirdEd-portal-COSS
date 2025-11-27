/**
 * Token-based proxy middleware for NodeBB API calls
 * Uses bearer tokens instead of session-based UIDs
 * Completely automatic - no manual token setup required
 */

const NodeBBTokenManager = require('../helpers/NodeBBTokenManager');
const proxy = require('express-http-proxy');

function createTokenBasedProxy(discussions_middleware) {
    const tokenManager = new NodeBBTokenManager(discussions_middleware);

    return function proxyObjectWithToken() {
        const proxyUtils = require('../proxy/proxyUtils');
        const logger = require('sb_logger_util_v2');

        return proxy(discussions_middleware, {
            // Add token to request headers instead of body
            proxyReqOptDecorator: function (proxyReqOpts, srcReq) {
                // Apply existing header decorations
                proxyReqOpts = proxyUtils.decorateRequestHeaders(discussions_middleware)(proxyReqOpts, srcReq);
                
                return new Promise(async (resolve, reject) => {
                    try {
                        // Get NodeBB token for the user (completely automatic)
                        const token = await tokenManager.getTokenForUser(srcReq);
                        
                        if (token) {
                            // Check if it's our custom token format
                            if (token.startsWith('sunbird_')) {
                                // For custom tokens, we need to handle authentication differently
                                const tokenPayload = tokenManager.validateCustomToken(token);
                                if (tokenPayload) {
                                    // Add both token and _uid for compatibility
                                    proxyReqOpts.headers['X-Sunbird-Token'] = token;
                                    if (srcReq.body && typeof srcReq.body === 'object') {
                                        srcReq.body['_uid'] = tokenPayload.uid;
                                    }
                                    console.log('Added custom Sunbird token for user:', srcReq.session.userId);
                                } else {
                                    // Token invalid, fallback to _uid
                                    this.fallbackToUID(srcReq);
                                }
                            } else {
                                // Standard NodeBB bearer token
                                proxyReqOpts.headers['Authorization'] = `Bearer ${token}`;
                                console.log('Added NodeBB bearer token for user:', srcReq.session.userId);
                            }
                        } else {
                            // Token generation failed, use fallback
                            this.fallbackToUID(srcReq);
                        }
                        
                        resolve(proxyReqOpts);
                    } catch (error) {
                        logger.error('Error adding NodeBB token to request:', error);
                        // Fallback to _uid method
                        this.fallbackToUID(srcReq);
                        resolve(proxyReqOpts);
                    }
                });
            },
            
            proxyReqPathResolver: function (req) {
                let urlParam = req.originalUrl;
                console.log("Automatic token-based request:", urlParam);
                
                // For write operations, we'll use token-based auth instead of _uid
                return require('url').parse(discussions_middleware + urlParam).path;
            },

            userResDecorator: (proxyRes, proxyResData, req, res) => {
                try {
                    const data = JSON.parse(proxyResData.toString('utf8'));
                    
                    // Handle token expiration by clearing cache
                    if (proxyRes.statusCode === 401 && req.session.userId) {
                        console.log('Token expired, clearing cache for user:', req.session.userId);
                        tokenManager.clearTokenCache(req.session.userId);
                        
                        // For 401 errors, try to regenerate token automatically
                        // This will happen on the next request
                    }
                    
                    // Store NodeBB UID if returned in response (for backward compatibility)
                    if (data.result && data.result.userId && data.result.userId.uid) {
                        const nodebb_uid = data.result.userId.uid;
                        req.session['nodebb_uid'] = nodebb_uid;
                        console.log('Stored NodeBB UID in session:', nodebb_uid);
                    }
                    
                    if (req.method === 'GET' && proxyRes.statusCode === 404 && 
                        (typeof data.message === 'string' && 
                         data.message.toLowerCase() === 'API not found with these values'.toLowerCase())) {
                        res.redirect('/');
                    } else {
                        return proxyUtils.handleSessionExpiry(proxyRes, proxyResData, req, res, data);
                    }
                } catch (err) {
                    logger.error({message: err});
                    return proxyUtils.handleSessionExpiry(proxyRes, proxyResData, req, res);
                }
            },

            // Helper method for fallback authentication
            fallbackToUID: function(srcReq) {
                let uid = srcReq.session['nodebb_uid'] || srcReq.session.userId;
                if (uid && srcReq.body && typeof srcReq.body === 'object') {
                    srcReq.body['_uid'] = uid;
                    console.log('Fallback: Added _uid to request body:', uid);
                }
            }
        });
    };
}

module.exports = createTokenBasedProxy;