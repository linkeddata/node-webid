# node-webid

Node.js module with tools to help using WebID (http://www.webid.info).

## Installation

```
$ npm install webid --save
```

## Features

- [x] Retrieve a webID ()
  ```
webid.get(uri, callback)
  ```
- [x] Verify a WebID
  ```
webid.verify(certificate, callback)
```


## Example

Basic usage:

```javascript
var webid = require('webid');
webid.verify(certificate, function (err, result) {
  if (err) {
    //An error occurred
  }
  //Success! User is identified
});
```

## Licence

The lib is available under MIT Licence: http://www.opensource.org/licenses/MIT

