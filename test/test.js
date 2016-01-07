var webid = require('../')
var tls = require('../tls')
var chai = require('chai')
var fs = require('fs')
var expect = chai.expect

var validCert = {
  subject: { O: 'WebID', CN: 'Nicola Greco (test) [on test_nicola.databox.me]' },
  issuer: { O: 'WebID', CN: 'Nicola Greco (test) [on test_nicola.databox.me]' },
  subjectaltname: 'URI:https://test_nicola.databox.me/profile/card#me',
  modulus: 'C62AE4CE77A8D915527F79EE1B5365099A35A3BF8E4AA68ED7CBF4D6B966ACE0FCAD79DE66A0EA89FF5EF8DAB2619F51E2F28227C9AA594BA3A4176723BA00813D8F8C738359F6240DF8FADD1A7AE56F2B24E7329A189E1065E3E7C2CEC96CC57CD9D3BF782DC15C11FBEFD24E536C46E8E1285BEC27CB3CC6C295595F18BC564A6ACA45ABCB8AD0C6617F42F5151DDB1A42513BE7AA9E2593DFDBB03938C15136C202C61E59DFE7C563F56301B5B29F91C03A9C92458BA26918E22CB137B998FF76EC85E97D16424078A949F491E348D9E33A43C9D5D938C6E12B2F2015FA2C1A950E28C6ECC6DD70CE228275DBB4C085BC4063DA24178F5B13601E3E6CE17F',
  exponent: '10001',
  valid_from: 'Jan  1 00:00:00 2000 GMT',
  valid_to: 'Dec 31 23:59:59 2049 GMT',
  fingerprint: '17:09:CB:F5:8D:D7:49:BB:36:45:B8:96:01:C9:0F:0D:E7:56:5B:C0',
  serialNumber: '2A'
}

describe('WebID', function () {
  describe('TLS', function () {
    describe('verifyKey', function () {
      it('should fail to verify unhandled profile mimeType-s', function (done) {
        tls.verifyKey(
            validCert,
            'https://test_nicola.databox.me/profile/card#me',
            '',
            'text/html',
            function (err, result) {
              expect(err).to.equal('Cound not load/parse profile data')
              done()
            })
      })
    })

    describe('verify', function () {
      //this.timeout(10000)

      it('valid certificate should have a uri as result', function (done) {
        tls.verify(validCert, function (err, result) {
          expect(err).to.not.exist
          expect(result).to.equal('https://test_nicola.databox.me/profile/card#me')
          done()
        })
      })

      it('should reject a webID uri not found', function (done) {
        var cert = {
          subjectaltname: 'URI:https://example.com/profile/card#me',
          modulus: validCert.modulus,
          exponent: validCert.exponent
        }
        tls.verify(cert, function (err, result) {
          expect(err.message).to.equal('Failed to retrieve WebID from https://example.com/profile/card#me: HTTP 404')
          done()
        })
      })

      it('should reject a certificate that does not match exponent or modulus', function(done) {
        var cert_invalid_exponent = {
          subjectaltname: validCert.subjectaltname,
          modulus: validCert.modulus,
          exponent: '10101' // invalid exponent
        }
        var cert_invalid_modulus = {
          subjectaltname: validCert.subjectaltname,
          modulus: validCert.modulus.substr(0, validCert.modulus.length - 1) + 'A', // invalid modulus
          exponent: validCert.exponent
        }

        tls.verify(cert_invalid_exponent, function (err, result) {
          expect(err.message).to.equal('Certificate public key not found in the user\'s profile')

          tls.verify(cert_invalid_modulus, function (err, result) {
            expect(err.message).to.equal('Certificate public key not found in the user\'s profile')
            done()
          })
        })
      })

      it('should report certificateProvidedSAN if certificate is missing', function (done) {
        var cert = null
        tls.verify(cert, function (err, result) {
          expect(err.message).to.equal('No certificate given')
          done()
        })
      })

      it('should report certificateProvidedSAN if certificate is empty', function (done) {
        var cert = {}
        tls.verify(cert, function (err, result) {
          expect(err.message).to.equal('Empty Subject Alternative Name field in certificate')
          done()
        })
      })

      it('should report missingModulus if only `URI:` is present', function (done) {
        var cert_only_uri = {
          subjectaltname: validCert.subjectaltname
        }

        webid('tls').verify(cert_only_uri, function (err, result) {
          expect(err.message).to.equal('Missing modulus value in client certificate')
          done()
        })
      })
    })

    describe('generate', function () {
      it('should create a valid certificate', function (done) {
        // Read in the spkac.cnf file.
        var spkacFile
        try {
            spkacFile = fs.readFileSync(__dirname+'/spkac.cnf')
            spkacFile = new Buffer(spkacFile)
        } catch (err) {
            expect(err).to.not.exist
        }

        expect(spkacFile).to.exist

        var opts = {
            spkac: spkacFile,
            agent: 'https://corysabol.databox.me/profile/card#me'
        }
        tls.generate(opts, function (err, cert) {
          expect(err).to.not.exist
          expect(cert).to.exist
          tls.verify(cert.ldCert, function (err, result) {
              expect(err).not.to.exist
              expect(result).to.equal('https://corysabol.databox.me/profile/card#me')
              done()
          })
        })
      })
    })
  })
})
