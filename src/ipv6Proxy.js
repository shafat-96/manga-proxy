const crypto = require('crypto');
const os = require('os');
const { spawn } = require('child_process');
const http = require('http');
const https = require('https');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { HttpProxyAgent } = require('http-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

// --- CONFIG via env ---
const SHARED_SECRET = process.env.I6_SHARED_SECRET || 'c';
const VERSION = '1.0.0';
const IPV6_PREFIX = process.env.I6_IPV6_PREFIX || '2001:41d0:601:1100';
const IPV6_SUBNET = process.env.I6_IPV6_SUBNET || '5950';
const INTERFACE = process.env.I6_INTERFACE || 'ens3';
const REQUEST_TIMEOUT = Number(process.env.I6_REQUEST_TIMEOUT || 30) * 1000;
const DEBUG = /^(1|true|yes)$/i.test(process.env.I6_DEBUG || 'false');
const ENABLE_ASSIGN = /^(1|true|yes)$/i.test(process.env.I6_ENABLE_ASSIGN || 'false');
const REQUIRE_TOKEN = /^(1|true|yes)$/i.test(process.env.I6_REQUIRE_TOKEN || 'false');

function logDebug(...args){ if (DEBUG) console.log('[i6]', ...args); }

function randomIPv6() {
  // Build an IPv6 by combining prefix + subnet + random hextets to total 8
  const prefParts = String(IPV6_PREFIX || '').split(':').filter(Boolean);
  const subParts = String(IPV6_SUBNET || '').split(':').filter(Boolean);
  const fixedCount = prefParts.length + subParts.length;
  const remaining = 8 - fixedCount;
  if (remaining <= 0 || remaining > 8) {
    logDebug('Invalid IPv6 config: too many hextets in prefix/subnet', IPV6_PREFIX, IPV6_SUBNET);
    return null; // signal to fallback
  }
  const buf = crypto.randomBytes(remaining * 2);
  const rand = [];
  for (let i = 0; i < remaining; i++) {
    const he = buf.readUInt16BE(i * 2).toString(16).padStart(4,'0');
    rand.push(he);
  }
  const parts = [...prefParts, ...subParts, ...rand];
  return parts.join(':');
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

function chooseFromList(listStr){
  const arr = String(listStr || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  if (!arr.length) return null;
  return arr[Math.floor(Math.random()*arr.length)];
}

function buildProxyAgents(proxyUrl, localAddress){
  try{
    const url = new URL(proxyUrl);
    const proto = url.protocol.toLowerCase();
    const commonOpts = { localAddress, keepAlive: true };
    if (proto.startsWith('socks')){
      const agent = new SocksProxyAgent(url, commonOpts);
      return { httpAgent: agent, httpsAgent: agent };
    }
    if (proto === 'http:' || proto === 'https:'){
      const httpAgent = new HttpProxyAgent(url, commonOpts);
      const httpsAgent = new HttpsProxyAgent(url, commonOpts);
      return { httpAgent, httpsAgent };
    }
  }catch(e){
    logDebug('Invalid proxy URL', proxyUrl, e.message);
  }
  return { httpAgent: undefined, httpsAgent: undefined };
}

function parseHeadersParam(headersStr){
  if (!headersStr) return {};
  try {
    const val = JSON.parse(headersStr);
    return (val && typeof val === 'object') ? val : {};
  } catch { return {}; }
}

// Strip headers that may reveal proxying or cause WAF blocks
const STRIP_REQ_HEADERS = new Set([
  'cf-connecting-ip',
  'cf-ipcountry',
  'cf-ray',
  'cf-visitor',
  'cf-worker',
  'cf-ew-via',
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-real-ip',
  'cdn-loop'
]);

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
  if (REQUIRE_TOKEN) {
    const apiToken = req.header('API-Token') || req.query.token;
    if (!apiToken || !validateApiToken(apiToken)){
      return res.status(401).send('Unauthorized: invalid API-Token');
    }
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
  const refererParam = req.query.referer;
  const cookiesParam = req.query.cookies; // raw cookie string
  const uaParam = req.query.ua; // override UA easily
  const proxyParam = req.query.proxy; // upstream proxy url
  const extraHeaders = parseHeadersParam(headersParam);

  let localIP = randomIPv6();
  if (os.platform() === 'linux'){
    const okIface = await checkInterface();
    if (!okIface) return res.status(500).send(`Interface ${INTERFACE} not found`);
    if (!localIP) {
      logDebug('Skipping IPv6 assign: invalid prefix/subnet config');
    }
    const added = localIP ? await addIPv6ToInterface(localIP) : true;
    if (!added) return res.status(500).send('Failed to configure IPv6 address');
    const ok = localIP ? await testIPv6Connectivity(localIP) : true;
    if (!ok){
      logDebug('IPv6 test failed, falling back to system default');
      localIP = undefined; // fallback
    }
  } else {
    // Non-linux: cannot assign addresses automatically; try anyway if already present
    logDebug('Non-linux system; using system default unless IPv6 exists');
    // We didn't assign the generated IPv6 to the interface; don't use it.
    localIP = undefined;
  }

  // Upstream proxy selection (query param wins, else env list)
  let upstream = proxyParam || chooseFromList(process.env.I6_PROXY_LIST);
  let httpAgent, httpsAgent;
  if (upstream){
    ({ httpAgent, httpsAgent } = buildProxyAgents(upstream, localIP));
  } else if (localIP){
    ({ httpAgent, httpsAgent } = pickAgents(localIP));
  } else {
    httpAgent = undefined;
    httpsAgent = undefined;
  }

  // Forward headers except host and strip proxy-identifying ones
  const fwdHeaders = {};
  for (const [k,v] of Object.entries(req.headers)){
    const key = k.toLowerCase();
    if (key === 'host') continue;
    if (STRIP_REQ_HEADERS.has(key)) continue;
    fwdHeaders[k] = v;
  }
  Object.assign(fwdHeaders, extraHeaders);
  // Apply defaults to look like a real browser if not provided
  if (uaParam) {
    fwdHeaders['user-agent'] = uaParam;
  } else if (!fwdHeaders['user-agent']) {
    fwdHeaders['user-agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
  }
  if (!fwdHeaders['accept']) {
    fwdHeaders['accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8';
  }
  if (!fwdHeaders['accept-language']) {
    fwdHeaders['accept-language'] = 'en-US,en;q=0.9';
  }
  if (refererParam && !fwdHeaders['referer']) {
    fwdHeaders['referer'] = refererParam;
    if (!fwdHeaders['origin']) {
      try {
        const origin = new URL(refererParam).origin;
        fwdHeaders['origin'] = origin;
      } catch {}
    }
  }
  if (cookiesParam) {
    fwdHeaders['cookie'] = cookiesParam;
  }

  const hasAbort = (typeof AbortController !== 'undefined');
  const controller = hasAbort ? new AbortController() : null;
  const timer = hasAbort ? setTimeout(()=> controller.abort(), REQUEST_TIMEOUT) : null;

  try{
    const method = req.method.toUpperCase();
    const init = { method, headers: fwdHeaders, agent: parsedUrl => parsedUrl.protocol === 'http:' ? httpAgent : httpsAgent };
    if (controller) init.signal = controller.signal;
    if (!['GET','HEAD'].includes(method)){
      init.body = req;
    }

    // Use node-fetch streaming
    const response = await fetch(targetUrl, init);
    const ab = await response.arrayBuffer();
    const bodyBuffer = Buffer.from(ab);

    res.status(response.status);
    const filtered = filterResponseHeaders(response.headers);
    for (const [k,v] of Object.entries(filtered)) res.setHeader(k, v);
    res.send(bodyBuffer);
  } catch (e){
    if (e.name === 'AbortError' || e.type === 'aborted'){
      res.status(504).send('Request timed out');
    } else {
      res.status(502).send(`Upstream error: ${e.message}`);
    }
  } finally {
    if (timer) clearTimeout(timer);
  }
}

module.exports = { ipv6ProxyHandler: handler };
