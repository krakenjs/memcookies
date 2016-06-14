memcookies
-----------

Persist cookies when in cookies disabled mode, by automatically encrypting them and storing them on the client side.

### Usage

Install:

`npm install --save memcookies`

Set up your middleware:

```javascript
var memcookies = require('memcookies');

app.use(memcookies({

    // Secret key used to encrypt the cookies before they are passed to the client
    encryptionKey: myKey,
}));
```

This should be invoked as the first middleware, before anything else requiring cookies to be present.

## Client side

Note that memcookies **only** works for ajax calls, not full-page posts, since it relies on being sent through custom http headers, and being persisted in memory on a single page.

### Persisting the cookies

Firstly, you will need to pass the cookies down in your initial page render. You can get the value as follows on the server-side, to insert into your initial html:

```javascript
// First we write out the head of our response. This ensures that all of the cookies which are going to be set, are set.
res.writeHead(200);

// Now we can render res.locals.encryptedCookies into our first page response
var templateContext = {
    encryptedCookies: JSON.stringify(res.locals.encryptedCookies)
};
```

You have two options for persisting the cookies on the client side:

#### 1. Manually

- On every ajax response, persist the `x-cookies` header
- On every ajax request, send the persisted `x-cookies` header

For example:

```javascript
var memcookies = {};

jQuery.ajax({
    type: 'POST',
    url: '/api/some/action',
    headers: {
        'x-cookies': JSON.stringify(memcookies)
    },
    success: function(data, textStatus, request){
        var newcookies = JSON.parse(request.getResponseHeader('x-cookies'));
        jQuery.extend(memcookies, newcookies);
    }
});
```

#### 2. Automatically, by patching XMLHttpRequest

```javascript
var memcookies = require('memcookies/client');
memcookies.setCookies(initialCookiesJSON);
memcookies.patchXhr();
```

This will hook into each request and response and automatically persist the cookies on the client side for you.
