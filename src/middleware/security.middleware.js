import aj from '#config/arcjet.js';
import logger from '#config/logger.js';
import { slidingWindow } from '@arcjet/node';

const securityMiddleware = async (req, res, next) => {
    try {
        const role = req.user?.role || 'guest';
        const userId = req.user?.id;

        let limit = 5;
        switch (role) {
            case 'admin':
                limit = 20;
                break;
            case 'user':
                limit = 10;
                break;
            case 'guest':
            default:
                limit = 5;
                break;
        }

        const client = aj.withRule(
            slidingWindow({
                mode: 'LIVE',
                interval: '1m',
                max: limit,
                name: `${role}-rate-limit`,
            })
        );

        // Pass user ID if authenticated so rate limits track per-user, falling back to IP
        const decision = await client.protect(req, {
            requested: 1,
            ...(userId && { fingerprint: userId }),
        });

        if (decision.isDenied()) {
            const context = {
                ip: req.ip,
                userId,
                role,
                userAgent: req.get('User-Agent'),
                path: req.path,
                method: req.method,
            };

            if (decision.reason.isBot()) {
                logger.warn('Bot request blocked', context);
                return res.status(403).json({
                    error: 'Forbidden',
                    message: 'Automated requests are not allowed',
                });
            }

            if (decision.reason.isShield()) {
                logger.warn('Shield blocked request', context);
                return res.status(403).json({
                    error: 'Forbidden',
                    message: 'Request blocked by security policy',
                });
            }

            if (decision.reason.isRateLimit()) {
                logger.warn('Rate limit exceeded', context);
                return res.status(429).json({
                    error: 'Too Many Requests',
                    message: 'Rate limit exceeded. Please try again later.',
                });
            }

            // Fallback for any other denial reason
            return res.status(403).json({
                error: 'Forbidden',
                message: 'Access denied',
            });
        }

        next();
    } catch (e) {
        logger.error('Arcjet middleware error:', e);
        res.status(500).json({
            error: 'Internal server error',
            message: 'Something went wrong with security middleware',
        });
    }
};

export default securityMiddleware;
