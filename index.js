'use strict';

var onHeaders = require('on-headers');
var ppcryptutils = require('cryptutils-paypal');
var cookiejar = require('cookiejar');
var crypto = require('crypto');
var util = require('util');
var _ = require('underscore');


/*
    CSRF Error
    ----------

    A custom CSRF Error specifically for cases when we want to throw a 301 to the user's browser.
    Everything else is considered an unhandled error.
*/

function MemCookiesError(message) {
    this.message = this.code = 'EINVALIDMEMCOOKIES_' + message;
}

util.inherits(MemCookiesError, Error);

/*
    Hash
    ----

    Hash a string using sha256
*/

function hash(secret, text) {
    return crypto.createHmac('sha256', secret).update(text).digest('hex');
}


function hashCookies(secret, reqCookies, resCookies) {

    var allCookies = _.extend({}, reqCookies, resCookies || {});

    var allCookiesString = Object.keys(allCookies).sort().map(function(name) {
        return name + '=' + allCookies[name];
    }).join('; ') || '';

    return hash(secret, allCookiesString);
}

module.exports = function memCookies(configuration) {

    /*
     Mem Cookies
     -----------

     Hermes needs to support cookies disabled mode. As such, we need to store cookies somewhere
     other than the browser's cookie jar, when we detect that cookies are disabled.

     Since the app is stateless and powered totally by javascript, the optimal place for cookies
     is on the front-end. This middleware allows the front-end to store cookies, given the following limitations:

     1. Using the existing 'cookie' header is off limits. It is not possible to set this header for ajax requests,
     nor is it possible to read cookies for a response when they are set as HttpOnly. As such, we use a '_cookies'
     header instead.

     2. We do not want javascript to have free reign over these cookies, given that most of them are designed to be
     HttpOnly. As such, we encrypt all cookies on the way out, and decrypt them on the way back in. So cookies
     are now transparently handled on the front-end.

     3. We rely on the front-end to tell us when it's in cookies disabled mode.

     4. For the initial page render, we provide res._cookies for the renderer to drop on the page. The alternative
     is making an additional ajax request, in order to get the _cookies object in headers.

     5. Since the browser can no longer expire cookies on outgoing responses, we can instead do this on incoming
     requests, by encoding the expiry time into the encrypted cookie value. Also, we can set a hard ceiling
     on this expiry time of 20 minutes, given that the cookies are only intended to exist until the user is
     redirected from the page.

     */

    var ppcrypto = new ppcryptutils({ // eslint-disable-line new-cap
        encryptionAlgorithm: 'desx',
        macAlgorithm: 'sha1',
        encryptionKey: configuration.encryptionKey,
        macKey: configuration.macKey
    });

    function encrypt(text) {
        return ppcrypto.sealAndEncode(new Buffer(text)).toString();
    }

    function decrypt(encrypted_text) {
        return ppcrypto.decodeAndUnseal(encrypted_text).toString();
    }


    function parseData(data) {
        try {
            return data && JSON.parse(data) || '';
        } catch (e) {
            return '';
        }
    }

    return function (req, res, next) {

        var meta = (req.body && req.body.meta) || (req.query.meta && JSON.parse(req.query.meta)) || {};

        // Read encrypted cookies from request. I only want to do this when my front-end tells
        // me it's in cookies-disabled mode, and has actually sent me some cookies.
        // Encrypted cookies sent by the front-end
        var xCookies = parseData(req.header('X-cookies'));
        var xCookiesBody = meta['x-cookies'];

        if (!xCookies && xCookiesBody) {
            xCookiesBody = JSON.parse(xCookiesBody);
            var xCookiesHash = req.headers['x-cookies-hash'];

            if (!xCookiesHash) {
                throw new MemCookiesError('BODY_COOKIE_HASH_HEADER_MISSING');
            }

            if (hashCookies(configuration.encryptionKey, xCookiesBody) !== xCookiesHash) {
                throw new MemCookiesError('BODY_COOKIE_HASH_MISMATCH');
            }

            xCookies = xCookiesBody;
        }

        // If we are sent some cookies, we should decrypt them
        if (xCookies) {

            var now = (new Date()).getTime();

            // Loop over each sent cookie, join them, and add them to the header,
            // with the expectation that the cookie parser will later read from the header.
            req.headers.cookie = Object.keys(xCookies).map(function (encrypted_key) {

                // Encrypted cookies are in the form `key: [value, expiry]`
                var key = decrypt(encrypted_key);
                var payload = parseData(decrypt(xCookies[encrypted_key]));

                if (!key || !payload || !(payload.length >= 2)) {
                    return;
                }

                var val = payload[0];
                var expiry = payload[1];

                // If the cookie has expired, we should ignore it - the browser can no longer
                // expire cookies for us.
                if (expiry <= now) {
                    return;
                }

                // Return the cookie in the standard header format.
                return key + '=' + val;

            }).filter(Boolean).join('; ');
        }


        // Write cookies to response. I only want to do this when a) my front-end is in cookies disabled mode,
        // or b) when I'm doing a full page render, which will have no access to its headers.
        if (xCookies || !req.xhr) {

            var rawCookies = [];
            var setHeader = res.setHeader;

            res.setHeader = function (name, value) {

                if (name.toLowerCase() === 'set-cookie') {

                    if (value instanceof Array) {
                        value.forEach(function(subvalue) {
                            if (rawCookies.indexOf(subvalue) === -1) {
                                rawCookies.push(subvalue);
                            }
                        });
                    }
                    else {
                        rawCookies.push(value);
                    }

                    if (!xCookies) {
                        return setHeader.apply(this, arguments);
                    }

                } else {
                    return setHeader.apply(this, arguments);
                }
            };

            // Listen for response headers to be sent, so we can be sure all cookies have been dropped
            onHeaders(res, function () {

                // Maximum expiry time should be 20 minutes from now
                var maxExpiry = (new Date()).getTime() + (20 * 60 * 1000); // eslint-disable-line no-extra-parens

                // Mapping of encrypted cookies
                var cookies = {};

                // Loop each of these cookies and parse the key/value
                rawCookies.forEach(function (cookie) {
                    cookie = cookiejar.Cookie(cookie); // eslint-disable-line new-cap

                    var payload = [
                        cookie.value,
                        // Expiry should be either the set expiry, or 20 mins, whichever is smaller.
                        // The purpose of this is to mitigate against replay attacks using these cookies.
                        Math.min(cookie.expiration_date, maxExpiry)
                    ];

                    cookies[encrypt(cookie.name)] = encrypt(JSON.stringify(payload));
                });

                res.locals.encryptedCookies = cookies;

                if (xCookies || !req.headers.cookie) {
                    res.setHeader('X-cookies', JSON.stringify(cookies));
                    res.setHeader('x-cookies-hash', hashCookies(configuration.encryptionKey, xCookies, cookies));
                }
            });
        }

        next();
    };
};

