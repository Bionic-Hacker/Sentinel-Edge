// SentinelEdge SPA router (CloudFront Function, viewer request; default behaviour only, so it
// never touches /api/*). A path without a file extension is a client-side route: serve
// index.html, as nginx's try_files does locally. Files (/assets/app.js) pass through unchanged.
function handler(event) {
  var request = event.request;
  var last = request.uri.split('/').pop();
  if (last === '' || last.indexOf('.') === -1) {
    request.uri = '/index.html';
  }
  return request;
}
