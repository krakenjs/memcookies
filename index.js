'use strict';

var onHeaders = require('on-headers');
var ppcryptutils = require('cryptutils-paypal');
var cookiejar = require('cookiejar');

module.exports = {

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

    memCookies: function (configuration) {

        var ppcrypto = new ppcryptutils({
            encryptionAlgorithm: 'desx',
            macAlgorithm: 'sha1',
            encryptionKey: configuration.encryptionKey,
            macKey: configuration.macKey
        });

        function encrypt(text) {
            var result;

            ppcrypto.sealAndEncode(new Buffer(text), function (encrypted_text) {
                result = encrypted_text;
            });

            return result;
        }

        function decrypt(encrypted_text) {
            var result;

            ppcrypto.decodeAndUnseal(encrypted_text, function (text) {
                result = text.toString();
            });

            return result;
        }


        return function (req, res, next) {

            // Read encrypted cookies from request. I only want to do this when my front-end tells
            // me it's in cookies-disabled mode, and has actually sent me some cookies.

            // Encrypted cookies sent by the front-end

            var memCookies = req.header('X-cookies');

            // If we are sent some cookies, we should decrypt them

            if (memCookies) {

                memCookies = JSON.parse(memCookies);
                var now = (new Date()).getTime();

                // Loop over each sent cookie, join them, and add them to the header,
                // with the expectation that the cookie parser will later read from the header.

                req.headers.cookie = Object.keys(memCookies).map(function (encrypted_key) {

                    // Encrypted cookies are in the form `key: [value, expiry, userAgent]`

                    var key = decrypt(encrypted_key);
                    var payload = JSON.parse(decrypt(memCookies[encrypted_key]));
                    var val = payload[0];
                    var expiry = payload[1];
                    var userAgent = payload[2];

                    // If the cookie has expired, we should ignore it - the browser can no longer
                    // expire cookies for us.

                    if (expiry <= now) {
                        return;
                    }

                    // If the user-agent does not match, we should fail hard

                    if (userAgent !== req.header('User-agent')) {
                        res.send(401);
                        throw new Error('memCookies: user-agent mismatch');
                    }

                    // Return the cookie in the standard header format.

                    return key + '=' + val;

                }).filter(Boolean).join('; ');
            }


            // Write cookies to response. I only want to do this when a) my front-end is in cookies disabled mode,
            // or b) when I'm doing a full page render, which will have no access to its headers.

            if (memCookies || !req.xhr) {

                // Listen for response headers to be sent, so we can be sure all cookies have been dropped

                onHeaders(res, function () {

                    // Maximum expiry time should be 20 minutes from now

                    var maxExpiry = (new Date()).getTime() + (20 * 60 * 1000);

                    // Get the raw cookies into a normalized array of raw cookie strings

                    var rawCookies = res._headers['set-cookie'] || [];
                    rawCookies = typeof rawCookies === 'string' ? [rawCookies] : rawCookies;

                    // Mapping of encrypted cookies

                    var cookies = {};

                    // Loop each of these cookies and parse the key/value

                    rawCookies.forEach(function (cookie) {
                        cookie = cookiejar.Cookie(cookie);

                        var payload = [

                            cookie.value,

                            // Expiry should be either the set expiry, or 20 mins, whichever is smaller.
                            // The purpose of this is to mitigate against replay attacks using these cookies.

                            Math.min(cookie.expiration_date, maxExpiry),

                            // Adding a user-agent provides a degree of indirection against replay attacks

                            req.header('User-agent')
                        ];

                        cookies[encrypt(cookie.name)] = encrypt(JSON.stringify(payload));
                    });

                    // If our request is asking for headers, we should give it a header.

                    if (memCookies) {
                        res.setHeader('X-cookies', JSON.stringify(cookies));
                    }

                    // Otherwise save cookies in the res for whatever renderer needs them later

                    else {
                        res.locals.encryptedCookies = cookies;
                    }
                });
            }

            next();
        };
    }

};

