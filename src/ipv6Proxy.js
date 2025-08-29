const crypto = require('crypto');
const os = require('os');
const { spawn } = require('child_process');
const http = require('http');
const https = require('https');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

// --- CONFIG via env ---
const SHARED_SECRET = process.env.I6_SHARED_SECRET || 'rXPACddng7mFAbjPP4feLFS1maXg3vpW';
const VERSION = '1.0.0';
const IPV6_PREFIX = process.env.I6_IPV6_PREFIX || '2a01:e5c0:2d74';
const IPV6_SUBNET = process.env.I6_IPV6_SUBNET || '1000';
const INTERFACE = process.env.I6_INTERFACE || 'ens3';
const REQUEST_TIMEOUT = Number(process.env.I6_REQUEST_TIMEOUT || 30) * 1000;
const DEBUG = /^(1|true|yes)$/i.test(process.env.I6_DEBUG || 'false');
const ENABLE_ASSIGN = /^(1|true|yes)$/i.test(process.env.I6_ENABLE_ASSIGN || 'false');

function logDebug(...args){ if (DEBUG) console.log('[i6]', ...args); }

function randomIPv6() {
  const buf = crypto.randomBytes(8);
  const a = buf.readUInt16BE(0).toString(16).padStart(4,'0');
  const b = buf.readUInt16BE(2).toString(16).padStart(4,'0');
  const c = buf.readUInt16BE(4).toString(16).padStart(4,'0');
  const d = buf.readUInt16BE(6).toString(16).padStart(4,'0');
  return `${IPV6_PREFIX}:${IPV6_SUBNET}:${a}:${b}:${c}:${d}`;
}

function deriveDynamicKey(){
  const nowBucket = Math.floor(Date.now() / 1000 / (3*60)) * (3*60);
  return Buffer.from(String(nowBucket), 'utf8');
}

function validateApiToken(token){
  try {
    const dynamicKey = deriveDynamicKey();
    const expected = crypto.createHmac('sha256', dynamicKey).update('proxy-access').digest('hex');
    return crypto.timingSafeEqual(Buffer.from(token||'', 'utf8'), Buffer.from(expected, 'utf8'));
  } catch (e) {
    logDebug('validate token error', e.message);
    return false;
  }
}

function ensureUrlHasScheme(url){
  if (!/^https?:\/\//i.test(url)) return `https://${url}`;
  return url;
}

function runCmd(cmd){
  return new Promise((resolve)=>{
    const proc = spawn(cmd, { shell: true });
    let out = '', err='';
    proc.stdout.on('data', d=> out += d.toString());
    proc.stderr.on('data', d=> err += d.toString());
    proc.on('close', code=> resolve({code, out, err}));
  });
}

async function checkInterface(){
  const {code, out, err} = await runCmd('ip link show');
  if (code !== 0){
    console.warn('Failed to list interfaces:', err||out);
    return false;
  }
  const ok = out.includes(INTERFACE);
  if (!ok){
    console.warn(`Interface ${INTERFACE} not found. Available:\n${out}`);
  }
  return ok;
}

async function addIPv6ToInterface(ip){
  if (!ENABLE_ASSIGN) return true; // skip adding if disabled
  logDebug('Adding IPv6 to iface', ip);
  const {code, err, out} = await runCmd(`ip -6 addr add ${ip}/128 dev ${INTERFACE}`);
  if (code !== 0 && !/File exists/i.test(err)){
    console.warn('Failed to add IPv6:', err||out);
    return false;
  }
  return true;
}

async function testIPv6Connectivity(ip){
  return new Promise((resolve)=>{
    try {
      const sock = require('dgram').createSocket('udp6');
      sock.bind({ address: ip }, ()=>{
        try{
          sock.connect(53, '2001:4860:4860::8888', ()=>{
            sock.close();
            resolve(true);
          });
        }catch(e){ sock.close(); resolve(false); }
      });
      sock.on('error', ()=> resolve(false));
    } catch(e){ resolve(false); }
  });
}

function pickAgents(localAddress){
  return {
    httpAgent: new http.Agent({ localAddress, keepAlive: true }),
    httpsAgent: new https.Agent({ localAddress, keepAlive: true })
  };
}

function parseHeadersParam(headersStr){
  if (!headersStr) return {};
  try {
    const val = JSON.parse(headersStr);
    return (val && typeof val === 'object') ? val : {};
  } catch { return {}; }
}

function filterResponseHeaders(headers){
  const skip = new Set([
    'transfer-encoding',
    'content-length',
    'connection',
    'keep-alive',
    'server'
  ]);
  const out = {};
  for (const [k,v] of headers.entries()){
    if (!skip.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}

async function handler(req, res){
  const apiToken = req.header('API-Token');
  if (!apiToken || !validateApiToken(apiToken)){
    return res.status(401).send('Unauthorized: invalid API-Token');
  }

  if (req.method === 'GET' && !req.query.url){
    // health/info
    if (os.platform() !== 'linux'){
      return res.status(200).send(`i6.js running (v${VERSION}) on ${os.platform()}`);
    }
    const { out } = await runCmd('ip -6 addr show');
    return res.status(200).send(`i6.js running (v${VERSION})\n${out}`);
  }

  const targetRaw = req.query.url;
  if (!targetRaw) return res.status(400).send('Missing url');

  const targetUrl = ensureUrlHasScheme(targetRaw);
  const headersParam = req.query.headers;
  const extraHeaders = parseHeadersParam(headersParam);

  let localIP = randomIPv6();
  if (os.platform() === 'linux'){
    const okIface = await checkInterface();
    if (!okIface) return res.status(500).send(`Interface ${INTERFACE} not found`);
    const added = await addIPv6ToInterface(localIP);
    if (!added) return res.status(500).send('Failed to configure IPv6 address');
    const ok = await testIPv6Connectivity(localIP);
    if (!ok){
      logDebug('IPv6 test failed, falling back to system default');
      localIP = undefined; // fallback
    }
  } else {
    // Non-linux: cannot assign addresses automatically; try anyway if already present
    logDebug('Non-linux system; using system default unless IPv6 exists');
  }

  const { httpAgent, httpsAgent } = localIP ? pickAgents(localIP) : { httpAgent: undefined, httpsAgent: undefined };

  // Forward headers except host
  const fwdHeaders = {};
  for (const [k,v] of Object.entries(req.headers)){
    if (k.toLowerCase() !== 'host') fwdHeaders[k] = v;
  }
  Object.assign(fwdHeaders, extraHeaders);

  const controller = new AbortController();
  const timer = setTimeout(()=> controller.abort(), REQUEST_TIMEOUT);

  try{
    const method = req.method.toUpperCase();
    const init = { method, headers: fwdHeaders, agent: parsedUrl => parsedUrl.protocol === 'http:' ? httpAgent : httpsAgent, signal: controller.signal };
    if (!['GET','HEAD'].includes(method)){
      init.body = req;
    }

    // Use node-fetch streaming
    const response = await fetch(targetUrl, init);
    const bodyBuffer = await response.buffer();

    res.status(response.status);
    const filtered = filterResponseHeaders(response.headers);
    for (const [k,v] of Object.entries(filtered)) res.setHeader(k, v);
    res.send(bodyBuffer);
  } catch (e){
    if (e.name === 'AbortError'){
      res.status(504).send('Request timed out');
    } else {
      res.status(502).send(`Upstream error: ${e.message}`);
    }
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { ipv6ProxyHandler: handler };
