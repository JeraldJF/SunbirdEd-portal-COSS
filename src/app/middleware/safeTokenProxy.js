/**
 * Safe wrapper for NodeBB token-based authentication
 * Falls back gracefully if advanced features are not available
 */

const _ = require('lodash');

function createSafeTokenProxy(discussions_middleware) {
    // Return a function that tries to use advanced token auth but falls back safely
    return function safeTokenProxy() {
        try {
            // Try to load the advanced token manager
            const NodeBBTokenManager = require('../helpers/NodeBBTokenManager');
            const proxy = require('express-http-proxy');
            const proxyUtils = require('../proxy/proxyUtils');
            const { logger } = require('@project-sunbird/logger');
            
            const tokenManager = new NodeBBTokenManager(discussions_middleware);
            
            // Helper method for fallback authentication
            function fallbackToUID(srcReq) {
                let uid = srcReq.session['nodebb_uid'] || srcReq.session.userId;
                if (uid && srcReq.body && typeof srcReq.body === 'object') {
                    srcReq.body['_uid'] = uid;
                    console.log('Fallback: Added _uid to request body:', uid);
                }
            }
            
            return proxy(discussions_middleware, {
                proxyReqOptDecorator: function (proxyReqOpts, srcReq) {
                    // Apply existing header decorations
                    proxyReqOpts = proxyUtils.decorateRequestHeaders(discussions_middleware)(proxyReqOpts, srcReq);
                    
                    // Try to get token, but don't fail if it doesn't work
                    return new Promise(async (resolve, reject) => {
                        try {
                            const token = await tokenManager.getTokenForUser(srcReq);
                            
                            if (token) {
                                if (token.startsWith('sunbird_')) {
                                    const tokenPayload = tokenManager.validateCustomToken(token);
                                    if (tokenPayload) {
                                        proxyReqOpts.headers['X-Sunbird-Token'] = token;
                                        if (srcReq.body && typeof srcReq.body === 'object') {
                                            srcReq.body['_uid'] = tokenPayload.uid;
                                        }
                                        console.log('Added custom Sunbird token for user:', srcReq.session.userId);
                                    } else {
                                        fallbackToUID(srcReq);
                                    }
                                } else {
                                    proxyReqOpts.headers['Authorization'] = `Bearer ${token}`;
                                    console.log('Added NodeBB bearer token for user:', srcReq.session.userId);
                                }
                            } else {
                                fallbackToUID(srcReq);
                            }
                            
                            resolve(proxyReqOpts);
                        } catch (error) {
                            console.warn('Token generation failed, using fallback:', error.message);
                            fallbackToUID(srcReq);
                            resolve(proxyReqOpts);
                        }
                    });
                },
                
                proxyReqPathResolver: function (req) {
                    let urlParam = req.originalUrl;
                    return require('url').parse(discussions_middleware + urlParam).path;
                },

                userResDecorator: (proxyRes, proxyResData, req, res) => {
                    try {
                        const data = JSON.parse(proxyResData.toString('utf8'));
                        
                        // Handle token expiration by clearing cache
                        if (proxyRes.statusCode === 401 && req.session.userId) {
                            console.log('Authentication failed, will retry with fallback on next request');
                            if (tokenManager && tokenManager.clearTokenCache) {
                                tokenManager.clearTokenCache(req.session.userId);
                            }
                        }
                        
                        // Store NodeBB UID if returned in response
                        if (data.result && data.result.userId && data.result.userId.uid) {
                            const nodebb_uid = data.result.userId.uid;
                            req.session['nodebb_uid'] = nodebb_uid;
                        }
                        
                        if (req.method === 'GET' && proxyRes.statusCode === 404 && 
                            (typeof data.message === 'string' && 
                             data.message.toLowerCase() === 'API not found with these values'.toLowerCase())) {
                            res.redirect('/');
                        } else {
                            return proxyUtils.handleSessionExpiry(proxyRes, proxyResData, req, res, data);
                        }
                    } catch (err) {
                        console.error('Response processing error:', err);
                        return proxyUtils.handleSessionExpiry(proxyRes, proxyResData, req, res);
                    }
                }
            });
            
        } catch (error) {
            console.warn('Advanced token authentication not available, using basic fallback:', error.message);
            
            // Fallback to basic proxy with _uid injection
            const proxy = require('express-http-proxy');
            const proxyUtils = require('../proxy/proxyUtils');
            
            return proxy(discussions_middleware, {
                proxyReqOptDecorator: proxyUtils.decorateRequestHeaders(discussions_middleware),
                proxyReqPathResolver: function (req) {
                    let urlParam = req.originalUrl;
                    console.log("Basic fallback request:", urlParam);
                    
                    // Add UID to request
                    let uid = req.session['nodebb_uid'] || req.session.userId;
                    if (!_.isEmpty(req.body)) {
                        req.body['_uid'] = uid;
                    } else {
                        let query = require('url').parse(req.url).query;
                        if (query) {
                            const queryData = `&_uid=${uid}`;
                            urlParam += (urlParam.includes('?') ? queryData : `?_uid=${uid}`);
                        } else {
                            urlParam += `?_uid=${uid}`;
                        }
                    }
                    
                    return require('url').parse(discussions_middleware + urlParam).path;
                },
                userResDecorator: (proxyRes, proxyResData, req, res) => {
                    try {
                        const data = JSON.parse(proxyResData.toString('utf8'));
                        if (req.method === 'GET' && proxyRes.statusCode === 404) {
                            res.redirect('/');
                        } else {
                            return proxyUtils.handleSessionExpiry(proxyRes, proxyResData, req, res, data);
                        }
                    } catch (err) {
                        return proxyUtils.handleSessionExpiry(proxyRes, proxyResData, req, res);
                    }
                }
            });
        }
    };
}

module.exports = createSafeTokenProxy;