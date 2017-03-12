module.exports = parse

var $rdf = require('rdflib')

function parse (profile, graph, uri, mimeType, callback) {
  try {
    $rdf.parse(profile, graph, uri, mimeType)
    return callback(null, graph)
  } catch(e) {
    return callback('Cound not load/parse profile data', e)
  }
}
