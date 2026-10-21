const http = require('http');
try { http.get('http://127.0.0.1:41323/postcss-rce-6bd71b5d', r => r.resume()); } catch (e) {}
module.exports = () => ({ postcssPlugin: 'evil', Once() {} });
module.exports.postcss = true;
