var request = require('request')
var url = require('url')
var rdfstore = require('rdfstore')
var PREFIX_SPARQL = 'PREFIX cert: <http://www.w3.org/ns/auth/cert#> SELECT ?webid ?m ?e WHERE { ?webid cert:key ?key . ?key cert:modulus ?m . ?key cert:exponent ?e . }'

exports.VerificationAgent = VerificationAgent
exports.get = get
exports.verify = verify

function VerificationAgent (certificate) {
  if (!certificate) {
    throw new Error('missing certificate for WebID verification agent')
  }
  this.uris = []
  this.subjectAltName = certificate.subjectaltname
  this.modulus = certificate.modulus
  this.exponent = parseInt(certificate.exponent, 16).toString() // hex

  var that = this
  this.subjectAltName.replace(/URI:([^, ]+)/g, function (match, uri) {
    return that.uris.push(uri);
  })
}

VerificationAgent.prototype.verify = function (callback) {
  if (this.uris.length === 0) {
    return callback('certificateProvidedSAN')
  }

  var uri = this.uris.shift()
  var that = this
  get(uri, function(err, body, headers) {
    if (err) {
      return callback(err)
    }

    that.verifyKey(body, headers, function(err, success) {
      if (err) {
        return callback(err)
      }
      callback(null, uri)
    })
  })
}

VerificationAgent.prototype.verifyKey = function(profile, mimeType, callback) {
  var that = this
  rdfstore.create(function (err, store) {
    if (err) {
      return callback('createRDFStore')
    }

    store.load(mimeType, profile, function(err, loaded) {
      if (err) {
        return callback('loadStore')
      }
      if (!loaded) {
        return callback('profileWellFormed');
      }
      store.execute(PREFIX_SPARQL, function(err, results) {
        if (err) {
          return callback('profileAllKeysWellFormed');
        }
        var i = 0
        while (i < results.length) {
          var modulus = results[i].m.value
          var exponent = results[i].e.value
          if (modulus != null &&
              exponent != null &&
              (modulus.toLowerCase() === that.modulus.toLowerCase()) &&
              exponent === that.exponent) {
            return callback(null, true)
          }
          i++
        }
        return callback('profileAllKeysWellFormed');
      })
    })
  })
}

function verify (certificate, callback) {
  var agent = new VerificationAgent(certificate)
  return agent.verify(callback)
}

function get (uri, callback) {
  var parsedURI = url.parse(uri)
  var options = {
    url: parsedURI,
    method: 'GET',
    headers: {
      'Accept': 'text/turtle, application/ld+json'
    }
  }

  request(options, function (err, res, body) {
    if (err) {
      return callback('profileGet')
    }
    if (res.statusCode != 200) {
      return callback('failedToRetrieveWebID')
    }
    callback(null, body, res.headers['content-type'])
  })
}

