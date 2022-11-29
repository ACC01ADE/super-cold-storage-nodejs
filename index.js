'use strict';

const utf8encoder = require('utf8');

Object.defineProperty(String.prototype, 'removeX', {
  value: function () {
    let v = this;
    v = v.trim();
    if (v.toLowerCase().startsWith('0x')) {
      v = v.substring(2);
    }
    return v.trim();
  },
});

Object.defineProperty(String.prototype, 'toHex', {
  value: function () {
    let str = utf8encoder.encode(this);
    let hex = '';
    // remove \u0000 padding from either side
    str = str.replace(/^(?:\u0000)*/, '');
    str = str.split('').reverse().join('');
    str = str.replace(/^(?:\u0000)*/, '');
    str = str.split('').reverse().join('');
    for (let i = 0, l = str.length; i < l; i++) {
      let code = str.charCodeAt(i);
      let n = code.toString(16);
      hex += n.length < 2 ? '0' + n : n;
    }
    return '0x' + hex;
  },
});

Object.defineProperty(String.prototype, 'toBuffer', {
  value: function () {
    const hexString = this.removeX();
    let result = [];
    for (let i = 0; i < hexString.length; i += 2) {
      result.push(parseInt(hexString.substring(i, i + 2), 16));
    }
    return Uint8Array.from(result);
  },
});

Object.defineProperty(String.prototype, 'hexify', {
  value: function (bytes) {
    if (typeof bytes === 'undefined' || bytes == null || bytes == '' || bytes < 0) {
      bytes = Math.ceil(str.length / 2);
    }
    let v = this;
    v = v.removeX();
    v = v.padStart(bytes * 2, '0');
    v = '0x' + v;
    return v;
  },
});

Object.defineProperty(Number.prototype, 'hexify', {
  value: function (bytes) {
    let str = this.toString(16);
    if (typeof bytes === 'undefined' || bytes == null || bytes == '' || bytes < 0) {
      bytes = Math.ceil(str.length / 2);
    }
    return str.hexify(bytes);
  },
});

Object.defineProperty(Uint8Array.prototype, 'toString', {
  value: function () {
    return Buffer.from(this).toString('hex').hexify(this.length);
  },
});

const utf = 'utf8'; // use this encoding for reading files
const utf_8 = 'utf-8'; // use this encoding for headers
const charset = '; charset=' + utf_8; // append this to content-type header

const root_dir = '/srv/www/nodejs';
const ssl_dir = '/srv/www/nodejs/ssl';

const fs = require('fs');
const tls = require('tls');
const http = require('http');
const https = require('https');
const execSync = require('child_process').execSync;
const secp = require('@noble/secp256k1');
const { keccak_256 } = require('@noble/hashes/sha3');

execSync(
  [
    'openssl',
    'req',
    '-newkey',
    'rsa:2048',
    '-x509',
    '-sha256',
    '-days 10',
    '-nodes',
    '-out ' + ssl_dir + '/internal.crt',
    '-keyout ' + ssl_dir + '/internal.key',
    '-subj "/C=FR/ST=Ile-de-France/L=Paris/O=ACC01ADE/OU=Super Cold Storage/CN=supercoldstorage.local"',
  ].join(' '),
  { cwd: root_dir, shell: '/bin/sh', stdio: 'pipe' }
);

const toChecksumAddress = function (input) {
  input = input.removeX().toLowerCase();
  let hash = keccak_256(Buffer.from(input, utf)).toString(16).removeX();
  let output = '0x';
  for (let i = 0, l = input.length; i < l; i++) {
    if (parseInt('0x0' + hash[i], 16) >= 8) {
      output += input[i].toUpperCase();
    } else {
      output += input[i];
    }
  }
  return output;
};

const getObjectAddress = function (id) {
  const pubkeyFile = root_dir + '/yubihsm/pubkey';
  fs.writeFileSync(pubkeyFile, '', { encoding: utf, flag: 'w' });
  execSync(
    [
      'yubihsm-shell',
      '--connector yhusb://',
      '-p password',
      '-a get-public-key',
      '-i ' + id,
      '--outformat bin',
      '--out ' + pubkeyFile,
    ].join(' '),
    { cwd: root_dir, shell: '/bin/sh', stdio: 'pipe' }
  );
  let publicKey = fs.readFileSync(pubkeyFile).toString('hex');
  publicKey = publicKey.substring(publicKey.length - 128, publicKey.length);
  let address = Buffer.from(keccak_256(Buffer.from(publicKey, 'hex')))
    .slice(-20)
    .toString('hex');
  return address;
};

const getYubiHSMKeys = function () {
  const objectsFile = root_dir + '/yubihsm/objects';
  fs.writeFileSync(objectsFile, '', { encoding: utf, flag: 'w' });
  execSync(
    [
      'yubihsm-shell',
      '--connector yhusb://',
      '-p password',
      '-a list-objects',
      '-A any',
      '-t any',
      '--out ' + objectsFile,
    ].join(' '),
    { cwd: root_dir, shell: '/bin/sh', stdio: 'pipe' }
  );
  const foundObjects = [
    ...fs
      .readFileSync(objectsFile, utf)
      .matchAll(
        /^id:\s(0x[0-9a-f]{4}),\stype:\sasymmetric-key,\salgo:\seck256,\ssequence:\s(\d+)\slabel:\s([^\n]+)$/gim
      ),
  ];
  let objMap = {};
  for (let i = 0, l = foundObjects.length; i < l; i++) {
    let obj = foundObjects[i];
    let id = obj[1];
    let sequence = obj[2];
    let label = obj[3];
    let address = getObjectAddress(id);
    objMap[address] = { id, sequence, label, address };
  }
  return objMap;
};
const keys = getYubiHSMKeys();

const msgFile = root_dir + '/yubihsm/msg';
const sigFile = root_dir + '/yubihsm/sig';

const signCommand = function (id) {
  return [
    'yubihsm-shell',
    '--connector',
    'yhusb://',
    '-p password',
    '-a sign-ecdsa',
    '-i ' + id,
    '-A ecdsa-keccak256',
    '--in ' + msgFile,
    '--informat hex',
    '--out ' + sigFile,
    '--outformat hex',
  ].join(' ');
};

const ecdsaSign = function (wallet, msgHash) {
  fs.writeFileSync(sigFile, '', { encoding: utf, flag: 'w' });
  fs.writeFileSync(msgFile, msgHash.removeX(), { encoding: utf, flag: 'w' });
  execSync(signCommand(keys[wallet].id), { cwd: root_dir, shell: '/bin/sh', stdio: 'pipe' });
  return fs.readFileSync(sigFile, utf);
};

// "\x19Ethereum Signed Message:\n32"
const ethMsgPre = '0x19457468657265756d205369676e6564204d6573736167653a0a3332';

const ssl_key = fs.readFileSync(ssl_dir + '/internal.key', utf);
const ssl_cert = fs.readFileSync(ssl_dir + '/internal.crt', utf);
const cert_hex = ssl_cert.toHex();

const secureContext = {
  '127.0.0.1': tls.createSecureContext({
    key: ssl_key,
    cert: ssl_cert,
  }),
};
const httpsOptions = {
  SNICallback: function (domain, callback) {
    callback(null, secureContext['127.0.0.1']);
  },
  key: ssl_key,
  cert: ssl_cert,
};

const getHeaders = function (additionalHeaders) {
  let h = {
    'Content-Type': 'application/json' + charset,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'content-type, cookie, set-cookie, session-cookie, set-session-cookie, *',
    'Access-Control-Expose-Headers': '*',
    'Access-Control-Allow-Credentials': 'true',
  };
  if (typeof additionalHeaders === 'object') {
    Object.keys(additionalHeaders).map(function (objectKey, index) {
      h[objectKey] = additionalHeaders[objectKey];
    });
  }
  return h;
};

const AllowAccess = function (requestHeaders) {
  let ah = {};
  if (typeof requestHeaders.origin !== 'undefined') {
    if (requestHeaders.origin == null || requestHeaders.origin == 'null') {
      requestHeaders.origin = '*';
    }
    ah['Access-Control-Allow-Origin'] = requestHeaders.origin;
  }
  if (typeof requestHeaders['access-control-request-headers'] !== 'undefined') {
    ah['Access-Control-Allow-Headers'] = requestHeaders['access-control-request-headers'] + ', *';
  }
  return getHeaders(ah);
};

var uploadLimit = 1024 * 1024 * 1; // 1Mb

const processPost = function (request, response, callback) {
  if (typeof request.fullUrl !== 'undefined' && request.fullUrl != null) {
    request.url = request.fullUrl;
  }
  let totalSize = 0;
  let chunks = [];
  let threw = false;
  if (typeof callback !== 'function') {
    throw new Error('missing callback function');
  }
  request.on('data', function (chunk) {
    chunks.push(chunk);
    totalSize += Buffer.byteLength(chunk);
    if (totalSize > uploadLimit) {
      threw = true;
      request.post = null;
      response.writeHead(413, 'Payload Too Large', getHeaders({ 'Content-Type': 'text/plain' + charset }));
      response.end();
      request.connection.destroy();
      callback();
    }
  });
  request.on('end', function () {
    if (!threw) {
      request.post = Buffer.concat(chunks);
      callback();
    }
  });
};

const HttpServerLogic = function (request, response) {
  console.log(request.url);
  response.writeHead(200, 'OK', {
    'Content-Type': 'text/plain' + charset,
  });
  response.end(cert_hex, utf);
};

const NotFound = function (request, response, message) {
  let error = message ? message : 'Endpoint does not exist';
  response.writeHead(404, 'NOT FOUND', AllowAccess(request.headers));
  response.end(JSON.stringify({ error }), utf);
};

const sign = function (wallet, message) {
  message = Buffer.from(keccak_256(message.toBuffer())).toString('hex').removeX();
  const rawSig = ecdsaSign(wallet, message);
  let decodedSig = secp.Signature.fromDER(rawSig);
  // to find the proper recovery value, we try both options
  const ecdsaPoint = [
    secp.Point.fromSignature(message, decodedSig, 0),
    secp.Point.fromSignature(message, decodedSig, 1),
  ];
  const address = [
    Buffer.from(keccak_256(ecdsaPoint[0].toRawBytes(false).slice(1)))
      .slice(-20)
      .toString('hex'),
    Buffer.from(keccak_256(ecdsaPoint[1].toRawBytes(false).slice(1)))
      .slice(-20)
      .toString('hex'),
  ];
  let recoveryValue = 0;
  if (address[1] == wallet) {
    recoveryValue = 1;
  }
  if (decodedSig.hasHighS()) {
    decodedSig = decodedSig.normalizeS();
    recoveryValue = recoveryValue === 0 ? 1 : 0;
  }
  const signatureHash = decodedSig.toCompactHex() + (recoveryValue + 27).toString(16).padStart(2, '0');
  const signature = {
    r: '0x' + signatureHash.substring(0, 64),
    s: '0x' + signatureHash.substring(64, 128),
    v: parseInt('0x' + signatureHash.substring(128, 130)),
  };
  console.log({ signature });
  return signature;
};

const ServerLogic = function (request, response) {
  console.log(request.url);
  let validWallet = false;
  let wallet = null;
  if (/^\/(0x|)[\da-f]{40}\//i.test(request.url)) {
    wallet = request.url.split('/')[1].removeX().toLowerCase();
    if (wallet in keys) {
      validWallet = true;
    }
  }
  if (request.method == 'OPTIONS') {
    response.writeHead(200, 'OK', AllowAccess(request.headers));
    response.end('{}', utf);
  } else if (request.method == 'POST') {
    processPost(request, response, function () {
      // we have a valid wallet address provided
      if (validWallet) {
        if (request.url.split('/')[2] == 'signTransaction') {
          const payload = JSON.parse(request.post.toString(utf));
          console.log('payload', '/signTransaction', payload);
          response.writeHead(200, 'OK', AllowAccess(request.headers));
          response.end(JSON.stringify({ signature: sign(wallet, payload.message) }), utf);
        } else if (request.url.split('/')[2] == 'signMessage') {
          const payload = JSON.parse(request.post.toString(utf));
          console.log('payload', '/signMessage', payload);
          let message = payload.message.removeX();
          if (message.length != 64) {
            if (!(message.length % 2 === 0 && /^[\da-f]+$/i.test(message))) {
              message = message.toHex();
            }
            message = Buffer.from(keccak_256(message.toBuffer())).toString('hex').removeX();
          }
          message = ethMsgPre + message;
          response.writeHead(200, 'OK', AllowAccess(request.headers));
          response.end(JSON.stringify({ signature: sign(wallet, message) }), utf);
        } else {
          NotFound(request, response);
        }
      } else {
        response.writeHead(400, 'Bad Request', AllowAccess(request.headers));
        response.end(
          JSON.stringify({
            error: wallet ? 'Account not currently loaded or supported by device' : 'Invalid account provided in URL',
          }),
          utf
        );
      }
    });
  } else if (request.method == 'GET') {
    if (request.url == '/accounts') {
      console.log('payload', '/accounts');
      console.log('accounts', { accounts: Object.keys(keys) });
      response.writeHead(200, 'OK', AllowAccess(request.headers));
      response.end(
        JSON.stringify({
          accounts: Object.keys(keys).map((e) => {
            return toChecksumAddress(e);
          }),
        }),
        utf
      );
    } else if (request.url.split('/')[2] == 'getLabel') {
      if (validWallet) {
        console.log('payload', '/getLabel');
        console.log('label', { label: toChecksumAddress(wallet) });
        response.writeHead(200, 'OK', AllowAccess(request.headers));
        response.end(JSON.stringify({ label: toChecksumAddress(wallet) }), utf);
      } else {
        response.writeHead(400, 'Bad Request', AllowAccess(request.headers));
        response.end(
          JSON.stringify({
            error: wallet ? 'Account not currently loaded or supported by device' : 'Invalid account provided in URL',
          }),
          utf
        );
      }
    } else {
      NotFound(request, response);
    }
  } else {
    NotFound(request, response);
  }
};

const httpServer = http.createServer(HttpServerLogic);
httpServer.listen(80); // http
const httpsServer = https.createServer(httpsOptions, ServerLogic);
httpsServer.listen(443); // https

console.log('Server running at http://127.0.0.1:' + 80 + '/');
console.log('Server running at https://127.0.0.1:' + 443 + '/');
