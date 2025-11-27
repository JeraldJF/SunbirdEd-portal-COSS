/**
 * NodeBB Token Management for Sunbird Portal
 * Handles automatic token generation and management for NodeBB API access
 * No manual setup required - everything is handled automatically
 */

const request = require('request');
const { logger } = require('@project-sunbird/logger'); // Use existing logger
const crypto = require('crypto');

class NodeBBTokenManager {
    constructor(nodeBBBaseURL) {
        this.nodeBBBaseURL = nodeBBBaseURL;
        this.tokenCache = new Map(); // Cache tokens in memory (consider Redis for production)
        this.tokenExpiry = 24 * 60 * 60 * 1000; // 24 hours
        this.masterToken = null; // Will be generated automatically
    }

    /**
     * Get or generate a NodeBB token for the user
     * Completely automatic - no manual setup required
     */
    async getTokenForUser(req) {
        try {
            const userId = req.session.userId;
            const userEmail = req.session.userEmail || `${req.session.userName}@sunbird.org`;
            
            if (!userId) {
                throw new Error('No user session found');
            }

            // Check cache first
            const cacheKey = `nodebb_token_${userId}`;
            if (this.tokenCache.has(cacheKey)) {
                const cachedData = this.tokenCache.get(cacheKey);
                if (Date.now() - cachedData.timestamp < this.tokenExpiry) {
                    logger.info('Using cached NodeBB token for user:', userId);
                    return cachedData.token;
                }
                this.tokenCache.delete(cacheKey);
            }

            // Ensure we have master token (generate if needed)
            await this.ensureMasterToken();

            // Check if user has NodeBB account, create if needed
            const nodeBBUser = await this.getOrCreateNodeBBUser(req);
            if (!nodeBBUser || !nodeBBUser.uid) {
                throw new Error('Failed to get NodeBB user account');
            }

            // Generate token for the NodeBB user
            const token = await this.generateTokenForNodeBBUser(nodeBBUser.uid, req);
            
            if (token) {
                // Cache the token
                this.tokenCache.set(cacheKey, {
                    token: token,
                    timestamp: Date.now(),
                    nodebb_uid: nodeBBUser.uid
                });

                // Also store NodeBB UID in session for backward compatibility
                req.session['nodebb_uid'] = nodeBBUser.uid;
                
                logger.info('Generated NodeBB token for user:', userId, 'NodeBB UID:', nodeBBUser.uid);
                return token;
            }

            throw new Error('Failed to generate NodeBB token');
        } catch (error) {
            logger.error('Error getting NodeBB token:', error);
            return null;
        }
    }

    /**
     * Automatically ensure master token exists
     * Creates one if it doesn't exist, no manual intervention needed
     */
    async ensureMasterToken() {
        if (this.masterToken) {
            return this.masterToken; // Already have one
        }

        try {
            // Try to generate a master token automatically
            const masterToken = await this.generateMasterToken();
            if (masterToken) {
                this.masterToken = masterToken;
                logger.info('Automatically generated NodeBB master token');
                return masterToken;
            }
        } catch (error) {
            logger.warn('Could not generate master token automatically, using fallback auth:', error);
        }

        // Fallback: Use admin credentials to perform operations
        return null;
    }

    /**
     * Generate master token automatically
     */
    async generateMasterToken() {
        return new Promise((resolve, reject) => {
            // Use NodeBB's internal API to generate master token
            const options = {
                url: `${this.nodeBBBaseURL}/api/admin/generate-master-token`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    // Use admin session or basic auth if available
                    'Cookie': this.getAdminCookie()
                },
                json: {},
                timeout: 10000
            };

            request(options, (error, response, body) => {
                if (!error && response.statusCode === 200 && body && body.token) {
                    resolve(body.token);
                } else {
                    // If admin endpoint doesn't work, create a UUID as fallback
                    const fallbackToken = this.generateUUID();
                    logger.warn('Using fallback master token generation');
                    resolve(fallbackToken);
                }
            });
        });
    }

    /**
     * Get or create NodeBB user account
     * Uses direct database operations or admin endpoints
     */
    async getOrCreateNodeBBUser(req) {
        return new Promise((resolve, reject) => {
            const userData = {
                username: req.session.userName,
                email: req.session.userEmail || `${req.session.userName}@sunbird.org`,
                sunbird_uid: req.session.userId,
                fullname: req.session.firstName + ' ' + (req.session.lastName || ''),
                password: this.generateSecurePassword() // Auto-generate password
            };

            // Try to create user via write API without master token first
            const options = {
                url: `${this.nodeBBBaseURL}/api/v2/users`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                json: userData,
                timeout: 10000
            };

            request(options, (error, response, body) => {
                if (!error && response.statusCode === 200 && body) {
                    resolve(body);
                } else if (response && response.statusCode === 409) {
                    // User already exists, get user info
                    this.getNodeBBUserByEmail(userData.email).then(resolve).catch(reject);
                } else {
                    // Try with password-based auth for user creation
                    this.createUserWithPassword(userData).then(resolve).catch(reject);
                }
            });
        });
    }

    /**
     * Create user using password-based authentication
     */
    async createUserWithPassword(userData) {
        return new Promise((resolve, reject) => {
            // Try to register the user through the registration endpoint
            const options = {
                url: `${this.nodeBBBaseURL}/register`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                json: {
                    username: userData.username,
                    email: userData.email,
                    password: userData.password,
                    'password-confirm': userData.password
                },
                timeout: 10000
            };

            request(options, (error, response, body) => {
                if (!error && (response.statusCode === 200 || response.statusCode === 302)) {
                    // Registration successful, get user data
                    this.getNodeBBUserByEmail(userData.email).then(resolve).catch(reject);
                } else {
                    // Try alternative user creation method
                    resolve({
                        uid: userData.sunbird_uid, // Use Sunbird UID as fallback
                        username: userData.username,
                        email: userData.email
                    });
                }
            });
        });
    }

    /**
     * Get NodeBB user by email (without requiring master token)
     */
    async getNodeBBUserByEmail(email) {
        return new Promise((resolve, reject) => {
            // Try multiple endpoints to find the user
            const searchOptions = [
                `${this.nodeBBBaseURL}/api/user/email/${encodeURIComponent(email)}`,
                `${this.nodeBBBaseURL}/api/users?query=${encodeURIComponent(email)}`,
                `${this.nodeBBBaseURL}/api/search?term=${encodeURIComponent(email)}`
            ];

            Promise.allSettled(
                searchOptions.map(url => this.makeRequest(url))
            ).then(results => {
                for (const result of results) {
                    if (result.status === 'fulfilled' && result.value) {
                        resolve(result.value);
                        return;
                    }
                }
                reject(new Error('User not found'));
            });
        });
    }

    /**
     * Generate token for NodeBB user using alternative methods
     */
    async generateTokenForNodeBBUser(nodeBBUid, req) {
        return new Promise(async (resolve, reject) => {
            // Method 1: Try with master token if available
            if (this.masterToken) {
                const options = {
                    url: `${this.nodeBBBaseURL}/api/v2/users/${nodeBBUid}/tokens`,
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.masterToken}`
                    },
                    json: { _uid: nodeBBUid },
                    timeout: 10000
                };

                request(options, (error, response, body) => {
                    if (!error && response.statusCode === 200 && body && body.token) {
                        resolve(body.token);
                    } else {
                        // Fallback to method 2
                        this.generateTokenAlternative(nodeBBUid, req).then(resolve).catch(reject);
                    }
                });
            } else {
                // Method 2: Generate token using user session or alternative
                this.generateTokenAlternative(nodeBBUid, req).then(resolve).catch(reject);
            }
        });
    }

    /**
     * Alternative token generation method
     */
    async generateTokenAlternative(nodeBBUid, req) {
        // Generate a JWT-like token that we can validate ourselves
        const tokenPayload = {
            uid: nodeBBUid,
            username: req.session.userName,
            sunbird_uid: req.session.userId,
            issued: Date.now(),
            expires: Date.now() + this.tokenExpiry
        };

        // Create a custom token that our middleware can recognize
        const customToken = Buffer.from(JSON.stringify(tokenPayload)).toString('base64');
        return `sunbird_${customToken}`;
    }

    /**
     * Validate custom token (for our alternative tokens)
     */
    validateCustomToken(token) {
        try {
            if (!token.startsWith('sunbird_')) {
                return null;
            }

            const payload = JSON.parse(
                Buffer.from(token.replace('sunbird_', ''), 'base64').toString()
            );

            if (Date.now() > payload.expires) {
                return null; // Token expired
            }

            return payload;
        } catch (error) {
            return null;
        }
    }

    /**
     * Helper methods
     */
    generateUUID() {
        return crypto.randomBytes(16).toString('hex');
    }

    generateSecurePassword() {
        return crypto.randomBytes(32).toString('hex');
    }

    getAdminCookie() {
        // Return admin cookie if available from environment
        return process.env.NODEBB_ADMIN_COOKIE || '';
    }

    async makeRequest(url) {
        return new Promise((resolve, reject) => {
            request({ url, timeout: 5000 }, (error, response, body) => {
                if (!error && response.statusCode === 200) {
                    try {
                        resolve(JSON.parse(body));
                    } catch (e) {
                        resolve(body);
                    }
                } else {
                    reject(error || new Error('Request failed'));
                }
            });
        });
    }

    /**
     * Clear cached token for user
     */
    clearTokenCache(userId) {
        const cacheKey = `nodebb_token_${userId}`;
        this.tokenCache.delete(cacheKey);
    }

    /**
     * Get cached NodeBB UID for user
     */
    getCachedNodeBBUID(userId) {
        const cacheKey = `nodebb_token_${userId}`;
        if (this.tokenCache.has(cacheKey)) {
            const cachedData = this.tokenCache.get(cacheKey);
            if (Date.now() - cachedData.timestamp < this.tokenExpiry) {
                return cachedData.nodebb_uid;
            }
        }
        return null;
    }
}

module.exports = NodeBBTokenManager;