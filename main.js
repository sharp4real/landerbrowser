'use strict';
// Silence Node.js deprecation warnings from transitive deps (e.g. discord-rpc → punycode)
process.noDeprecation = true;

// Suppress Electron ExtensionLoadWarning (MV2 deprecation) from stderr
const _stderrWrite = process.stderr.write.bind(process.stderr);
process.stderr.write = function(data, ...args) {
  if (typeof data === 'string' && data.includes('ExtensionLoadWarning')) return true;
  return _stderrWrite(data, ...args);
};

const {
  app, BrowserWindow, BrowserView,
  ipcMain, dialog, shell, session, Menu, clipboard, screen,
} = require('electron');
const path               = require('path');
const fs                 = require('fs');
const https              = require('https');
const { spawn }          = require('child_process');
const { pathToFileURL }  = require('url');
const os                 = require('os');
const { shouldBlock }    = require('./blocklist.js');

// Domains never blocked regardless of settings (needed for site functionality)
const BUILTIN_WHITELIST = [
  // TikTok — only core content/video delivery domains; tracker subdomains are NOT listed
  // so they can be blocked by shouldBlock() normally.
  'tiktok.com','tiktokv.com','tiktokcdn.com','tiktokcdn-us.com','ttwstatic.com',
  'ibytedtos.com','ibyteimg.com','byteoversea.com',
  // Spotify — ALL domains required for full functionality including DRM
  'spotify.com','*.spotify.com',
  'scdn.co','*.scdn.co',
  'spotifycdn.com','*.spotifycdn.com',
  'spotifycdn.net','*.spotifycdn.net',
  'pscdn.co','*.pscdn.co',
  'spotilocal.com','*.spotilocal.com',
  'audio-ak-spotify-com.akamaized.net',
  'spclient.wg.spotify.com','apresolve.spotify.com','dealer.spotify.com',
  'open.spotify.com','accounts.spotify.com','api.spotify.com',
  'www.spotify.com','play.spotify.com','login.spotify.com',
  'auth.spotify.com','api-partner.spotify.com','*.spotifycdn.net',
  '*.spotifycdn.com','*.spotifycdn.co',
  // Google — ALL auth, sign-in, and service domains must preserve headers intact.
  // Google's OAuth flow validates Referer, Sec-Fetch-*, and other headers across
  // redirects between these domains. Any stripping triggers the
  // "This browser may not be secure" block on accounts.google.com.
  'google.com','accounts.google.com','apis.google.com',
  'googleapis.com','googleusercontent.com','gstatic.com',
  'gmail.com','youtube.com','ytimg.com','ggpht.com',
  'translate.google.com', // For translation feature
  'translate.goog', '*.translate.goog', // Google's .translate.goog proxy (page translation)
  // Bing — Microsoft search engine needs proper headers to work
  'bing.com','www.bing.com',
  // NOTE: google-analytics.com and googletagmanager.com intentionally NOT listed here
  // so they remain blockable by shouldBlock(). They don't affect Google auth flows.
];

// Tracker/analytics subdomains that must be blocked even if their parent domain
// is in BUILTIN_WHITELIST. These take priority over the whitelist.
const TRACKER_FORCE_BLOCK = new Set([
  // TikTok analytics, logging, monitoring, and ad infrastructure
  'analytics.tiktok.com', 'log.tiktok.com', 'log-va.tiktok.com',
  'log-sg.tiktok.com', 'log-useast2a.tiktok.com', 'log-useast8.tiktok.com',
  'mon.tiktok.com', 'stats.tiktok.com', 'event.tiktok.com',
  'metrics.tiktok.com', 'monitor.tiktok.com', 'tracker.tiktok.com',
  'ads.tiktok.com', 'business.tiktok.com',
  // ByteDance tracking SDK and analytics infrastructure (not needed for playback)
  'snssdk.com', 'bdurl.net', 'musical.ly',
  'toblog.ctobsnssdk.com', 'lf16-tiktok-web.tiktokcdn.com',
  // Google tracker subdomains — force-block even though googleapis.com/gstatic.com
  // are in BUILTIN_WHITELIST for auth. These subdomains carry no auth traffic.
  'imasdk.googleapis.com',
  'pagead2.googlesyndication.com', 'tpc.googlesyndication.com',
  'stats.g.doubleclick.net', 'cm.g.doubleclick.net',
  'fundingchoicesmessages.google.com',
  'adservice.google.com',
  'ssl.google-analytics.com', 'analytics.google.com',
  'csi.gstatic.com',
]);

if (process.platform === 'win32') app.setAppUserModelId('com.lander.browser');

// Remove the automation flag Electron sets by default — Google checks this
// to determine if the browser is automated/non-standard. Must be set before
// any window is created (commandLine switches are read at startup).
app.commandLine.appendSwitch('disable-blink-features', 'AutomationControlled');

// ── ENHANCED PRIVACY ─────────────────────────────────────────────────────────

// Prevent IP leaks through WebRTC — hides local/VPN IPs but keeps WebRTC
// functional for video calls (Discord, Meet, etc.).
app.commandLine.appendSwitch('webrtc-ip-handling-policy', 'default_public_interface_only');

// ── Privacy-preserving network flags ─────────────────────────────────────────
// NOTE: --disable-background-networking is intentionally NOT used here.
// It also kills speculative DNS prefetch and TCP preconnect, which Chrome uses
// to warm connections before the user clicks — a major page-load speedup.
// Instead we use targeted flags that only disable the phone-home services:

// No Google field trials / A-B experiments (stops phoning home to Finch servers)
app.commandLine.appendSwitch('disable-field-trial-config');
// No component update pings (CRLSets, Widevine update checks, etc.)
app.commandLine.appendSwitch('disable-component-update');
// No Safe Browsing URL reporting to Google
app.commandLine.appendSwitch('disable-client-side-phishing-detection');
// Suppress Chrome's built-in translation offer (we have our own translate)
app.commandLine.appendSwitch('disable-translate');
// No default apps check
app.commandLine.appendSwitch('disable-default-apps');
// No spell check network requests (local dictionary still works)
app.commandLine.appendSwitch('disable-spell-check-service');
// No crash reporter phone-home
app.commandLine.appendSwitch('disable-crash-reporter');
// No Google account sync
app.commandLine.appendSwitch('disable-sync');
// Disable hyperlink auditing pings (<a ping="..."> attribute)
app.commandLine.appendSwitch('no-pings');
// Disable domain reliability monitoring (Chromium phones home on navigation errors)
app.commandLine.appendSwitch('disable-domain-reliability');
// Disable metrics reporting
app.commandLine.appendSwitch('metrics-recording-only');
// Disable network prediction / prefetching to prevent DNS leaks
app.commandLine.appendSwitch('disable-features', 'NetworkPrediction,OptimizationHints');
// Force partitioned third-party cookies (prevents cross-site tracking)
app.commandLine.appendSwitch('partitioned-cookies');

// ── Widevine CDM (enables DRM for Spotify, Netflix, etc.) ─────────────────────
// Priority order:
//   1. Lander's own downloaded CDM (no Chrome/Edge needed)
//   2. Chrome / Edge / Brave system install fallback
// If nothing is found at startup, widevineAutoDownload() runs after app ready
// and saves the CDM to userData — takes effect on next launch.
let _widevineLoaded = false;

(function tryLoadWidevine() {
  // ── Shared helpers ──────────────────────────────────────────────────────────
  const _sortVersions = arr => arr
    .filter(v => /^\d+\.\d+\.\d+\.\d+$/.test(v))
    .sort((a, b) => {
      const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
      for (let i = 0; i < 4; i++) { if (pa[i] !== pb[i]) return pb[i] - pa[i]; }
      return 0;
    });

  const _register = (cdmPath, version) => {
    app.commandLine.appendSwitch('widevine-cdm-path', cdmPath);
    app.commandLine.appendSwitch('widevine-cdm-version', version || '');
    _widevineLoaded = true;
    return true;
  };

  // ── 1. Lander's own downloaded CDM (userData/landerbrowser/WidevineCdm/<ver>/) ───
  function _tryOwnCdm() {
    let userData;
    try { userData = app.getPath('userData'); } catch { return false; }
    const base = path.join(userData, 'landerbrowser', 'WidevineCdm');
    if (!fs.existsSync(base)) return false;
    const dllName = process.platform === 'win32' ? 'widevinecdm.dll'
                  : process.platform === 'linux'  ? 'libwidevinecdm.so'
                  : 'libwidevinecdm.dylib';
    for (const ver of _sortVersions(fs.readdirSync(base))) {
      const cdmPath = path.join(base, ver, dllName);
      if (fs.existsSync(cdmPath)) {
        let version = ver;
        try { version = JSON.parse(fs.readFileSync(path.join(base, ver, 'manifest.json'), 'utf8')).version || ver; } catch {}
        return _register(cdmPath, version);
      }
    }
    return false;
  }

  // ── 2. Chrome/Edge "Application\<ver>\WidevineCdm" layout ──────────────────
  function _tryDir(base) {
    if (!fs.existsSync(base)) return false;
    for (const ver of _sortVersions(fs.readdirSync(base))) {
      const cdmPath = path.join(base, ver, 'WidevineCdm', '_platform_specific', 'win_x64', 'widevinecdm.dll');
      const manifest = path.join(base, ver, 'WidevineCdm', 'manifest.json');
      if (fs.existsSync(cdmPath) && fs.existsSync(manifest)) {
        try { return _register(cdmPath, JSON.parse(fs.readFileSync(manifest, 'utf8')).version || ''); } catch {}
      }
    }
    return false;
  }

  // ── 3. Chrome/Edge "User Data\WidevineCdm\<ver>" layout ────────────────────
  function _tryUserDataDir(base) {
    if (!fs.existsSync(base)) return false;
    for (const ver of _sortVersions(fs.readdirSync(base))) {
      const cdmPath = path.join(base, ver, '_platform_specific', 'win_x64', 'widevinecdm.dll');
      const manifest = path.join(base, ver, 'manifest.json');
      if (fs.existsSync(cdmPath) && fs.existsSync(manifest)) {
        try { return _register(cdmPath, JSON.parse(fs.readFileSync(manifest, 'utf8')).version || ver); } catch {}
      }
    }
    return false;
  }

  try {
    // Always check our own CDM first — works without any other browser installed
    if (_tryOwnCdm()) return;

    if (process.platform === 'win32') {
      const local  = process.env.LOCALAPPDATA || '';
      const prog   = process.env.PROGRAMFILES || 'C:\\Program Files';
      const prog86 = process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)';
      const userDataCandidates = [
        path.join(local, 'Google', 'Chrome', 'User Data', 'WidevineCdm'),
        path.join(local, 'Microsoft', 'Edge', 'User Data', 'WidevineCdm'),
        path.join(local, 'BraveSoftware', 'Brave-Browser', 'User Data', 'WidevineCdm'),
        path.join(prog,  'Google', 'Chrome', 'User Data', 'WidevineCdm'),
      ];
      let found = false;
      for (const c of userDataCandidates) { if (_tryUserDataDir(c)) { found = true; break; } }
      if (!found) {
        for (const c of [
          path.join(local,  'Google', 'Chrome', 'Application'),
          path.join(local,  'Microsoft', 'Edge', 'Application'),
          path.join(prog,   'Google', 'Chrome', 'Application'),
          path.join(prog86, 'Google', 'Chrome', 'Application'),
          path.join(prog,   'Microsoft', 'Edge', 'Application'),
        ]) { if (_tryDir(c)) break; }
      }
    } else if (process.platform === 'darwin') {
      const _tryMacCdm = (cdmPath, manifestPath) => {
        if (!fs.existsSync(cdmPath) || !fs.existsSync(manifestPath)) return false;
        try { return _register(cdmPath, JSON.parse(fs.readFileSync(manifestPath, 'utf8')).version || ''); } catch { return false; }
      };
      const _macBase = (n, f) =>
        `/Applications/${n}.app/Contents/Frameworks/${f}.framework/Versions/Current/Libraries/WidevineCdm`;
      const _ch = _macBase('Google Chrome', 'Google Chrome Framework');
      const _br = _macBase('Brave Browser', 'Brave Browser Framework');
      [
        [_ch + '/_platform_specific/mac_arm64/libwidevinecdm.dylib', _ch + '/manifest.json'],
        [_ch + '/_platform_specific/mac_x64/libwidevinecdm.dylib',   _ch + '/manifest.json'],
        [_br + '/_platform_specific/mac_arm64/libwidevinecdm.dylib',  _br + '/manifest.json'],
        [_br + '/_platform_specific/mac_x64/libwidevinecdm.dylib',    _br + '/manifest.json'],
      ].some(([cdm, mf]) => _tryMacCdm(cdm, mf));
    } else if (process.platform === 'linux') {
      const home = process.env.HOME || '';
      function _tryLinuxCdmDir(base) {
        if (!fs.existsSync(base)) return false;
        for (const ver of _sortVersions(fs.readdirSync(base))) {
          const cdmPath = path.join(base, ver, '_platform_specific', 'linux_x64', 'libwidevinecdm.so');
          const manifest = path.join(base, ver, 'manifest.json');
          if (fs.existsSync(cdmPath) && fs.existsSync(manifest)) {
            try { return _register(cdmPath, JSON.parse(fs.readFileSync(manifest, 'utf8')).version || ''); } catch {}
          }
        }
        return false;
      }
      for (const c of [
        path.join(home, '.config', 'google-chrome', 'WidevineCdm'),
        path.join(home, '.config', 'chromium', 'WidevineCdm'),
        path.join(home, '.var', 'app', 'com.google.Chrome', 'config', 'google-chrome', 'WidevineCdm'),
        path.join(home, '.var', 'app', 'org.chromium.Chromium', 'config', 'chromium', 'WidevineCdm'),
        path.join(home, 'snap', 'google-chrome', 'current', '.config', 'google-chrome', 'WidevineCdm'),
        '/opt/google/chrome/WidevineCdm',
        '/usr/lib/chromium/WidevineCdm',
        '/usr/lib/chromium-browser/WidevineCdm',
      ]) { if (_tryLinuxCdmDir(c)) break; }
    }
  } catch { /* Widevine unavailable — silently continue */ }
})();

// ── Widevine self-downloader ──────────────────────────────────────────────────
// Downloads Widevine CDM directly from Google's component update server —
// no Chrome or Edge installation required. Triggered at app ready when no
// CDM is found. The downloaded binary is stored in userData and loaded on
// the NEXT launch (commandLine switches must be set before app ready).

function _widevineDownloadBuffer(url) {
  return new Promise((resolve, reject) => {
    function follow(u) {
      const parsed = new URL(u);
      const opts = {
        hostname: parsed.hostname,
        path: parsed.pathname + parsed.search,
        headers: { 'User-Agent': 'GoogleUpdate/1.3.36.372 winhttp' },
      };
      https.get(opts, res => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return follow(res.headers.location);
        }
        if (res.statusCode !== 200) return reject(new Error('HTTP ' + res.statusCode));
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
      }).on('error', reject);
    }
    follow(url);
  });
}

function _widevineQueryUpdateServer() {
  return new Promise((resolve, reject) => {
    const osPlatform = process.platform === 'win32' ? 'win'
                     : process.platform === 'darwin' ? 'mac' : 'linux';
    const appid = 'oimompecagnajdejgnnjijobebaeignd';
    const body = Buffer.from(
      '<?xml version="1.0" encoding="UTF-8"?>' +
      '<request protocol="3.1" version="chrome-142.0.0.0" prodversion="142.0.0.0" lang="en-US" installsource="ondemandupdate">' +
      `<os platform="${osPlatform}" arch="x64"/>` +
      `<app appid="${appid}" version="0.0.0.0"><updatecheck/></app>` +
      '</request>',
      'utf8'
    );
    const req = https.request({
      hostname: 'update.googleapis.com',
      path: '/service/update2/crx',
      method: 'POST',
      headers: {
        'Content-Type': 'application/xml',
        'Content-Length': body.length,
        'User-Agent': 'GoogleUpdate/1.3.36.372 winhttp',
      },
      timeout: 12000,
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Widevine update server timeout')); });
    req.write(body);
    req.end();
  });
}

function _widevineParseUpdateXml(xml) {
  // Extract codebase URL (download prefix)
  const cbMatch   = xml.match(/codebase="([^"]+)"/);
  // Extract package filename (the .crx3 file)
  const nameMatch = xml.match(/name="([^"]+\.crx3?)"/);
  // Extract CDM version from manifest element
  const verMatch  = xml.match(/<manifest[^>]+version="(\d+\.\d+\.\d+\.\d+)"/);
  if (!cbMatch || !nameMatch || !verMatch) return null;
  return {
    version: verMatch[1],
    downloadUrl: cbMatch[1] + nameMatch[1],
  };
}

function _widevineExtractZipFromCrx3(buf) {
  // CRX3 = "Cr24" magic + version(4) + header_size(4) + protobuf_header(header_size) + ZIP
  if (buf.length < 12 || buf.toString('ascii', 0, 4) !== 'Cr24') throw new Error('Not a CRX file');
  if (buf.readUInt32LE(4) !== 3) throw new Error('Only CRX3 is supported');
  const zipStart = 12 + buf.readUInt32LE(8);
  if (zipStart >= buf.length) throw new Error('CRX3 header extends beyond file');
  return buf.slice(zipStart);
}

async function _widevineExtractFromZip(zipBuf, destDir) {
  // Pure Node.js ZIP extractor — no external dependencies, uses built-in zlib
  const zlib = require('zlib');
  const dllName = process.platform === 'win32' ? 'widevinecdm.dll'
                : process.platform === 'linux'  ? 'libwidevinecdm.so'
                : 'libwidevinecdm.dylib';
  const platformSubdir = process.platform === 'win32' ? '_platform_specific/win_x64'
                       : process.platform === 'linux'  ? '_platform_specific/linux_x64'
                       : (process.arch === 'arm64' ? '_platform_specific/mac_arm64' : '_platform_specific/mac_x64');
  const targetDll = `${platformSubdir}/${dllName}`;

  let dllWritten = false;
  let offset = 0;

  while (offset + 30 <= zipBuf.length) {
    const sig = zipBuf.readUInt32LE(offset);
    // Central directory or end-of-central-directory record — done scanning local entries
    if (sig === 0x02014b50 || sig === 0x06054b50) break;
    if (sig !== 0x04034b50) { offset++; continue; } // skip until local file header

    const compression = zipBuf.readUInt16LE(offset + 8);
    const compSize    = zipBuf.readUInt32LE(offset + 18);
    const fnLen       = zipBuf.readUInt16LE(offset + 26);
    const extraLen    = zipBuf.readUInt16LE(offset + 28);
    const filename    = zipBuf.toString('utf8', offset + 30, offset + 30 + fnLen).replace(/\\/g, '/');
    const dataOffset  = offset + 30 + fnLen + extraLen;

    const isDll      = filename === targetDll || filename.endsWith('/' + dllName);
    const isManifest = filename === 'manifest.json';

    if (isDll || isManifest) {
      const compressed = zipBuf.slice(dataOffset, dataOffset + compSize);
      let data;
      if (compression === 0) {
        data = compressed; // stored — no compression
      } else if (compression === 8) {
        data = zlib.inflateRawSync(compressed); // deflate — standard ZIP compression
      } else {
        throw new Error(`Unsupported ZIP compression method: ${compression}`);
      }
      const outPath = path.join(destDir, isDll ? dllName : 'manifest.json');
      fs.writeFileSync(outPath, data);
      if (isDll) dllWritten = true;
    }

    offset = dataOffset + compSize;
  }

  if (!dllWritten) throw new Error('CDM binary not found in CRX package');
}

async function widevineAutoDownload() {
  if (_widevineLoaded) return; // already loaded from disk at startup
  try {
    let userData;
    try { userData = app.getPath('userData'); } catch { return; }

    send('toast', 'Downloading Widevine DRM (needed for Spotify/Netflix)…', 'teal');

    const xml  = await _widevineQueryUpdateServer();
    const info = _widevineParseUpdateXml(xml);
    if (!info) throw new Error('Could not parse Widevine update server response');

    const { version, downloadUrl } = info;
    const destDir = path.join(userData, 'landerbrowser', 'WidevineCdm', version);
    fs.mkdirSync(destDir, { recursive: true });

    const crxBuf = await _widevineDownloadBuffer(downloadUrl);
    const zipBuf = _widevineExtractZipFromCrx3(crxBuf);
    await _widevineExtractFromZip(zipBuf, destDir);

    // Write a minimal manifest if the ZIP didn't contain one
    const mfPath = path.join(destDir, 'manifest.json');
    if (!fs.existsSync(mfPath)) fs.writeFileSync(mfPath, JSON.stringify({ version }));

    // Make the binary executable on Unix
    if (process.platform !== 'win32') {
      const dllName = process.platform === 'linux' ? 'libwidevinecdm.so' : 'libwidevinecdm.dylib';
      try { fs.chmodSync(path.join(destDir, dllName), 0o755); } catch {}
    }

    send('toast', `Widevine ${version} ready — restart Lander Browser for Spotify/Netflix DRM`, 'teal');
  } catch (err) {
    // Silently fail — DRM just won't work until a later attempt or manual install
    send('toast', 'Widevine download failed — DRM (Spotify/Netflix) may not work', 'err');
  }
}

// Allow audio/video autoplay without user gesture (needed for Music Player)
app.commandLine.appendSwitch('autoplay-policy', 'no-user-gesture-required');
// Prevent Chromium from EVER suspending background renderer processes or their media.
// This is the definitive fix for videos/audio pausing when a BV is detached from the window.
// JS-level overrides (visibility, blur, etc.) can race with native Chromium scheduler events;
// these flags disable the scheduler behaviour entirely at the process level.
app.commandLine.appendSwitch('disable-renderer-backgrounding');
app.commandLine.appendSwitch('disable-background-media-suspend');

// ── Default browser + external URL handling ──────────────────────────────────
// Register RAW as a capable handler for http/https at the OS level.
// On Windows 10/11 this writes the registry entries; user still selects via Settings.
// On macOS this may set it directly depending on OS version.
app.setAsDefaultProtocolClient('https');
app.setAsDefaultProtocolClient('http');

// Extract a navigable URL from a process argv array (set as default browser or open-with).
function getArgUrl(argv) {
  for (const a of (argv || []).slice(1)) {
    if (/^https?:\/\//i.test(a)) return a;
    if (/^file:\/\//i.test(a))   return a;
    // Windows: file path passed directly (e.g. double-click .html)
    if (/\.(html?|xhtml|pdf)$/i.test(a)) {
      try { if (fs.existsSync(a)) return pathToFileURL(a).href; } catch {}
    }
  }
  return null;
}

// ── Explicit userData path — prevents Chromium "Unable to move the cache" errors ──
// Without this, Electron picks an OS default that can conflict with other instances
// or trigger cache migration failures (Access Denied 0x5) on Windows.
app.name = 'lander-browser';
app.setPath('userData', require('path').join(app.getPath('appData'), 'lander-browser'));

// Single-instance lock: if RAW is already running and an external link is clicked,
// forward the URL to the existing window instead of opening a second instance.
const _gotSingleLock = app.requestSingleInstanceLock();
if (!_gotSingleLock) { app.quit(); }
app.on('second-instance', (_, argv) => {
  if (!win) return;
  if (win.isMinimized()) win.restore();
  win.focus();
  const url = getArgUrl(argv);
  if (url) createTab(url, true);
});

// macOS: link clicked in another app while RAW is already running
let _pendingExtUrl = null;
app.on('open-url', (event, url) => {
  event.preventDefault();
  if (win) createTab(url, true);
  else _pendingExtUrl = url;
});

const SPOOF_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36';
const SPOOF_UA_HINTS = '"Not_A Brand";v="8", "Chromium";v="142", "Google Chrome";v="142"';

// Pool of realistic user agents used when per-tab UA rotation is enabled.
const _UA_ROTATE_POOL = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
];

// ── Global UA fallback ─────────────────────────────────────────────────────────
// The deepest possible override — covers every WebContents that has NOT had
// setUserAgent() called explicitly (service workers, pre-flight auth checks,
// non-partitioned popup windows, etc.). Must be set BEFORE app.whenReady().
app.userAgentFallback = SPOOF_UA;

// Set the UA at the Chromium process level — applies to every renderer, service
// worker, and sub-frame before any JS runs, overriding Electron's own binary string.
app.commandLine.appendSwitch('user-agent', SPOOF_UA);

// ── Enable features — ONE call; Chromium only honours the last value ──────────
// HardwareMediaKeyHandling + MediaSessionService: media keys & OS media HUD.
// PlatformEncryptedMediaFoundation (win32 only): DRM via Media Foundation.
//
// NOTE: StoragePartitioning and BlockThirdPartyCookies are intentionally NOT
// enabled here. In Chromium 120+ (Electron 36+) these features operate BELOW
// Electron's webRequest layer and block third-party cookies/storage for DRM
// license servers (e.g. spclient.wg.spotify.com) even when those domains are
// whitelisted in our request handlers. Removing them fixes Widevine/Spotify DRM.
// Cross-site isolation is still enforced by our webRequest interceptors.
if (process.platform === 'win32') {
  app.commandLine.appendSwitch('enable-features',
    'HardwareMediaKeyHandling,MediaSessionService,PlatformEncryptedMediaFoundation');
} else {
  app.commandLine.appendSwitch('enable-features',
    'HardwareMediaKeyHandling,MediaSessionService');
}

// ── Disable features — ONE call; Chromium only honours the last value ─────────
// NetworkPrediction: no speculative pre-connections leaking browsing intent.
// DnsOverHttps: disable Chromium's built-in DoH (use OS resolver).
// PrefetchPrivacyChanges: keep prefetch from pinging third-party hosts.
// WebRtcHideLocalIpsWithMdns: expose real IP (mDNS can interfere with WebRTC).
// WebAuthentication*: suppress Windows Hello / FIDO2 / passkey dialogs.
app.commandLine.appendSwitch('disable-features',
  'NetworkPrediction,DnsOverHttps,PrefetchPrivacyChanges,' +
  'WebRtcHideLocalIpsWithMdns,WebAuthentication,WebAuthenticationCableSecondFactor,' +
  'WebAuthenticationPasskeysInBrowserWindow,WebAuthenticationRemoteDesktopSupport');
app.commandLine.appendSwitch('no-pings'); // suppress <a ping=> hyperlink auditing

// ── Anti-bot detection flags ─────────────────────────────────────────────────
// Remove Electron-specific infobars / first-run markers that differ from Chrome.
app.commandLine.appendSwitch('disable-infobars');
app.commandLine.appendSwitch('no-first-run');
app.commandLine.appendSwitch('no-default-browser-check');
// Disable component extensions (Chrome's built-in internal extensions like PDF
// viewer) — Electron loads different ones which can be detected via chrome.runtime.
app.commandLine.appendSwitch('disable-component-extensions-with-background-pages');
// Ensure the user-data-dir doesn't leak an Electron-specific path in error reports
app.commandLine.appendSwitch('disable-crash-reporter');
app.commandLine.appendSwitch('disable-gpu-shader-disk-cache'); // prevent GPU cache creation errors

// ── YouTube stealth ad-skip content script ────────────────────────────────────
// ── YouTube Ad Blocker (stealth, comprehensive) ───────────────────────────────
// Design:
//  • All injected identifiers are randomised per-injection — no static names to fingerprint
//  • Intercepts fetch/XHR to strip ad formats from YouTube player API responses
//  • CSS hides every known ad surface (display-ads, overlays, banners, companion ads)
//  • MutationObserver reacts only to ad-relevant DOM/attribute changes (low overhead)
//  • Speeds through video ads (mute + seek to end + auto-skip button click)
//  • Dismisses overlay ads, bot-check dialogs, and enforcement modals
//  • Saves/restores user mute/volume/playbackRate around each ad
//  • Works on initial page load AND YouTube SPA navigations
const YT_AD_SKIP = `(function(){
  if(window.location.pathname.indexOf('/shorts/')===0)return;

  // ── Randomised namespace so no static property name is detectable ────────────
  var _nsKey='__ytb_'+Math.random().toString(36).slice(2,9);
  var _styleId='s'+Math.random().toString(36).slice(2,11);
  var _prevNs=window.__ytAdNs;
  if(_prevNs){
    try{window[_prevNs]&&window[_prevNs].obs&&window[_prevNs].obs.disconnect();}catch(e){}
    try{window[_prevNs]&&window[_prevNs].iv&&clearInterval(window[_prevNs].iv);}catch(e){}
    try{window[_prevNs]&&window[_prevNs].wObs&&window[_prevNs].wObs.disconnect();}catch(e){}
    try{delete window[_prevNs];}catch(e){}
  }
  window.__ytAdNs=_nsKey;
  window[_nsKey]={};

  // ── Intercept fetch & XHR: strip ad formats from player/next API responses ──
  // This is the most reliable way to prevent ads at the data level.
  // We only modify responses from known YouTube player endpoints; everything else
  // is passed through unchanged so normal site functionality is unaffected.
  (function _patchNetwork(){
    function _cleanPlayerResp(obj){
      if(!obj||typeof obj!=='object')return obj;
      // Remove adPlacements, playerAds, and companionSlots from any object depth
      var AD_KEYS=['adPlacements','adSlots','playerAds','adBreakParams',
                   'adThrottlingModel','companionAdSlots','adErrorInterstitial',
                   'playerLegacyDesktopWatchAdsRenderer','adPreroll'];
      AD_KEYS.forEach(function(k){if(obj[k])obj[k]=[];});
      // Also clear the ad-related fields inside playerConfig
      if(obj.playerConfig&&obj.playerConfig.adConfig)obj.playerConfig.adConfig={};
      if(obj.playerConfig&&obj.playerConfig.mediaCommonConfig)
        delete obj.playerConfig.mediaCommonConfig.mediaUstreamerRequestConfig;
      return obj;
    }
    function _tryPatch(text){
      try{
        var j=JSON.parse(text);
        _cleanPlayerResp(j);
        // Also handle wrapped responses like  {[{"responseContext":...},...]}
        if(Array.isArray(j))j.forEach(_cleanPlayerResp);
        return JSON.stringify(j);
      }catch(e){return text;}
    }
    function _isAdUrl(url){
      return/\/(youtubei|player|next|browse)\//i.test(url)&&
             /youtube\.com|yt\.be/i.test(url);
    }
    // Patch fetch
    var _origFetch=window.fetch;
    window.fetch=function(input,init){
      var url=typeof input==='string'?input:(input&&input.url)||'';
      var p=_origFetch.apply(this,arguments);
      if(!_isAdUrl(url))return p;
      return p.then(function(resp){
        if(!resp.ok)return resp;
        var ct=resp.headers.get('content-type')||'';
        if(ct.indexOf('json')===-1)return resp;
        return resp.text().then(function(txt){
          var patched=_tryPatch(txt);
          return new Response(patched,{status:resp.status,statusText:resp.statusText,headers:resp.headers});
        });
      });
    };
    // Patch XHR
    var _origOpen=XMLHttpRequest.prototype.open;
    var _origSend=XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open=function(m,u){
      this._ytAbUrl=u||'';
      return _origOpen.apply(this,arguments);
    };
    XMLHttpRequest.prototype.send=function(){
      if(_isAdUrl(this._ytAbUrl||'')){
        this.addEventListener('readystatechange',function(){
          if(this.readyState!==4)return;
          var ct=this.getResponseHeader('content-type')||'';
          if(ct.indexOf('json')===-1)return;
          try{
            Object.defineProperty(this,'responseText',{get:function(){
              return _tryPatch(this._ytAbPatchedText||XMLHttpRequest.prototype.responseText.call(this));
            },configurable:true});
            this._ytAbPatchedText=_tryPatch(XMLHttpRequest.prototype.responseText.call(this)||'');
          }catch(e){}
        });
      }
      return _origSend.apply(this,arguments);
    };
  })();

  // ── CSS: hide every known non-video ad surface ──────────────────────────────
  (function _injectCSS(){
    if(document.getElementById(_styleId))return;
    var s=document.createElement('style');
    s.id=_styleId;
    s.textContent=
      // In-feed and display ads
      'ytd-promoted-sparkles-text-search-renderer,ytd-promoted-video-renderer,'+
      'ytd-display-ad-renderer,ytd-banner-promo-renderer,#masthead-ad,'+
      'ytd-ad-slot-renderer,ytd-in-feed-ad-layout-renderer,'+
      'ytd-action-companion-ad-renderer,ytd-companion-slot-renderer,'+
      'ytd-statement-banner-renderer,ytd-engagement-panel-section-list-renderer[target-id="engagement-panel-ads"],'+
      // Player ad overlays and containers
      '#player-ads,#player-ads>.ytd-watch-flexy,#frosted-glass-container,'+
      '.ytp-ad-overlay-container,.ytp-ce-covering-ad,.ytp-ce-element,'+
      '.ytp-ce-covering-overlay,.ytp-suggested-action,.ytp-ad-module,'+
      // Google/DoubleClick ad iframes
      '[id^="google_ads_iframe"],[id^="aswift_"],[id^="div-gpt-ad"],'+
      // Pause overlay ads
      '.ad-showing .ytp-pause-overlay,.ad-interrupting .ytp-pause-overlay,'+
      // Ad text badges and progress bars
      '.ytp-ad-text,.ytp-ad-preview-container,.ytp-ad-badge-container,'+
      '.ytp-ad-message-container,.ytp-ad-image-overlay,'+
      '.ytp-ad-overlay-ad-info-button-container,'+
      'ytd-player-legacy-desktop-watch-ads-renderer,'+
      '.ytp-ad-persistent-progress-bar-container,'+
      '.ytp-ad-progress-list,.ytp-ad-simple-ad-badge,'+
      // Companion / masthead ads
      'ytd-display-ad-renderer[slot],ytd-action-companion-ad-renderer[slot],'+
      '.ytd-video-masthead-ad-v3-renderer,#video-masthead-ad,'+
      'ytd-companion-slot-renderer[slot],'+
      // Feed ads (has-based selectors for modern YT layout engine)
      'ytd-rich-item-renderer:has(.ytd-ad-slot-renderer),'+
      'ytd-rich-section-renderer:has(ytd-statement-banner-renderer),'+
      // 2024/2025: new ad slot types
      'ytd-reel-shelf-renderer:has([is-ads]),'+
      'ytd-shelf-renderer:has(ytd-in-feed-ad-layout-renderer),'+
      'tp-yt-paper-dialog:has(ytd-enforcement-message-view-model),'+
      // Survey / research panels that interrupt viewing
      '.ytd-mealbar-promo-renderer'+
      '{display:none!important;visibility:hidden!important}';
    (document.head||document.documentElement).appendChild(s);
  })();

  var _wasInAd=false,_userMuted=false,_userRate=1,_userVolume=1,_restoreTimer=null;

  function _inAd(player){
    if(player&&(player.classList.contains('ad-showing')||
                player.classList.contains('ad-interrupting')))return true;
    if(document.querySelector('.ytp-ad-player-overlay-instream-info,.ytp-ad-persistent-progress-bar-container'))return true;
    var adText=document.querySelector('.ytp-ad-text,.ytp-ad-simple-ad-badge,.ytp-ad-badge');
    if(adText&&adText.offsetParent!==null)return true;
    var skipBtn=document.querySelector('.ytp-ad-skip-button,.ytp-ad-skip-button-modern,.ytp-skip-ad-button,.ytp-ad-skip-button-slot,.ytp-ad-skip-button-container');
    if(skipBtn&&skipBtn.offsetParent!==null)return true;
    var progList=document.querySelector('.ytp-ad-progress-list');
    if(progList&&progList.offsetParent!==null)return true;
    return false;
  }

  function _getVideo(){
    return document.querySelector('#movie_player video.html5-main-video')||
           document.querySelector('#movie_player video')||
           document.querySelector('video.html5-main-video')||
           document.querySelector('video');
  }

  function _act(){
    try{
      // 1. Click any visible skip button first — cleanest outcome, no seek needed
      var skipSel='.ytp-ad-skip-button-modern,.ytp-skip-ad-button,.ytp-ad-skip-button,'+
        '.ytp-ad-skip-button-slot .ytp-button,button.ytp-ad-skip-button-modern,'+
        '.ytp-ad-skip-button-container button,.ytp-ad-skip-button-slot button';
      var skipBtns=document.querySelectorAll(skipSel);
      for(var si=0;si<skipBtns.length;si++){
        var sb=skipBtns[si];
        if(sb&&sb.offsetParent!==null&&!sb.hidden&&sb.offsetWidth>0){
          sb.click();
          setTimeout(_act,300);
          return;
        }
      }

      var player=document.querySelector('#movie_player,.html5-video-player');
      var video=_getVideo();
      var inAd=_inAd(player);

      if(inAd&&video&&video.readyState>0){
        if(!_wasInAd){
          _userMuted=video.muted;
          _userRate=(video.playbackRate>2)?1:video.playbackRate;
          _userVolume=video.volume;
        }
        _wasInAd=true;
        if(!video.muted)video.muted=true;
        // Seek to near end first (fastest path), then also boost speed
        if(video.duration&&isFinite(video.duration)&&video.duration>0.1){
          try{video.currentTime=Math.max(0,video.duration-0.05);}catch(e){}
        }
        try{if(video.playbackRate<16)video.playbackRate=16;}catch(e){}
        if(video.paused&&video.readyState>=2)try{video.play();}catch(e){}
      } else if(_wasInAd&&!inAd){
        _wasInAd=false;
        if(_restoreTimer)clearTimeout(_restoreTimer);
        _restoreTimer=setTimeout(function(){
          var v=_getVideo();
          if(v){
            try{v.playbackRate=_userRate||1;}catch(e){}
            try{v.muted=_userMuted;}catch(e){}
            try{if(!_userMuted)v.volume=_userVolume;}catch(e){}
            if(v.paused&&v.readyState>=2)try{v.play();}catch(e){}
          }
          _restoreTimer=null;
        },400);
      }

      // 2. Close overlay ads
      document.querySelectorAll(
        '.ytp-ad-overlay-close-button,.ytp-ad-overlay-slot-close-button,'+
        '.ytp-suggested-action-badge-expanded-close-button,'+
        '.ytp-ad-overlay-close-container,.ytp-ad-skip-button-slot button'
      ).forEach(function(el){try{if(el.offsetParent!==null)el.click();}catch(e){}});

      // 3. Dismiss bot-check / ad-block enforcement dialogs
      // YouTube uses multiple dialog implementations — cover all known ones
      var enforceSel=
        'ytd-enforcement-message-view-model,'+
        'ytd-enforcement-message-view-model tp-yt-paper-button,'+
        'tp-yt-paper-dialog ytd-enforcement-message-view-model,'+
        'ytd-watch-modal tp-yt-paper-dialog,'+
        'ytd-modal-with-title-and-button-renderer';
      var dlg=document.querySelector(enforceSel);
      if(dlg&&dlg.offsetParent!==null){
        // Try the most common dismiss button patterns
        var dismissSel=
          'button[aria-label*="without" i],button[aria-label*="Continue" i],'+
          'button[aria-label*="Watch" i],button[aria-label*="Dismiss" i],'+
          'button[aria-label*="Got it" i],button[aria-label*="OK" i],'+
          '.yt-spec-button-shape-next--filled,.yt-spec-button-shape-next--tonal,'+
          'tp-yt-paper-button[dialog-confirm]';
        var watchBtn=dlg.querySelector(dismissSel);
        if(!watchBtn){
          var btns=dlg.querySelectorAll('button,.yt-spec-button-shape-next,tp-yt-paper-button');
          if(btns.length)watchBtn=btns[btns.length-1];
        }
        if(watchBtn)try{watchBtn.click();}catch(e){}
      }
    }catch(e){}
  }

  // ── MutationObserver — fires on ad-relevant class/node changes only ──────────
  var _obs=new MutationObserver(function(muts){
    var act=false;
    for(var i=0;i<muts.length;i++){
      var t=muts[i].target;
      if(muts[i].type==='attributes'&&t&&t.classList&&
        (t.classList.contains('ad-showing')||t.classList.contains('ad-interrupting'))){act=true;break;}
      var added=muts[i].addedNodes;
      for(var j=0;j<added.length;j++){
        var n=added[j];
        if(n.nodeType!==1)continue;
        var c=(n.className||'')+(n.id||'');
        if(c.indexOf('ytp-ad')!==-1||c.indexOf('ad-showing')!==-1||c.indexOf('ad-interrupt')!==-1||
           (n.tagName&&(n.tagName==='YTD-AD-SLOT-RENDERER'||n.tagName==='YTD-IN-FEED-AD-LAYOUT-RENDERER'))){act=true;break;}
      }
      if(act)break;
    }
    if(act)_act();
  });
  window[_nsKey].obs=_obs;

  // ── Polling fallback — active only when an ad is detected ───────────────────
  var _iv=setInterval(function(){
    var p=document.querySelector('#movie_player,.html5-video-player');
    if(_inAd(p)||_wasInAd)_act();
  },500);
  window[_nsKey].iv=_iv;

  function _attach(){
    var p=document.querySelector('#movie_player,.html5-video-player,ytd-player,ytd-app');
    if(p){
      _obs.observe(p,{childList:true,subtree:true,attributes:true,attributeFilter:['class']});
      window[_nsKey].wObs=null;
    } else {
      var _w=new MutationObserver(function(){
        var p2=document.querySelector('#movie_player,.html5-video-player,ytd-player');
        if(p2){
          _w.disconnect();
          window[_nsKey].wObs=null;
          _obs.observe(p2,{childList:true,subtree:true,attributes:true,attributeFilter:['class']});
        }
      });
      _w.observe(document.documentElement,{childList:true,subtree:false});
      window[_nsKey].wObs=_w;
    }
  }

  _attach();
  _act();
  setTimeout(_act,300);
  setTimeout(_act,900);
  setTimeout(_act,2200);
  setTimeout(_act,4500);
})();`;

// ── YouTube ad-tracking URLs to block at network level ────────────────────────
// Only ad analytics/impression/delivery/tracking endpoints are blocked.
// Video content endpoints (videoplayback, manifest, etc.) are never touched.
// NOTE: imasdk.googleapis.com is intentionally NOT blocked — it initialises the
// ad framework; blocking it makes YouTube's player hang on a black screen and
// prevents all video playback.
const YT_AD_BLOCK_PATTERNS = [
  // YouTube ad stats and tracking
  /youtube\.com\/api\/stats\/ads/i,
  /youtube\.com\/pagead\//i,
  /youtube\.com\/ptracking/i,
  /youtube\.com\/pagead\/paralleladview/i,
  /youtube\.com\/pagead\/adview/i,
  /youtube\.com\/pagead\/viewthroughconversion/i,
  /youtube\.com\/get_video_info\?.*adformat/i,
  // Ad-tagged QoE/watchtime pings only
  /youtube\.com\/api\/stats\/qoe\?.*adformat/i,
  /youtube\.com\/api\/stats\/watchtime\?.*(?:ad|ads_id)/i,
  // DoubleClick / Google Ads delivery
  /googleads\.g\.doubleclick\.net/i,
  /pubads\.g\.doubleclick\.net/i,
  /securepubads\.g\.doubleclick\.net/i,
  /static\.doubleclick\.net/i,
  /ad\.doubleclick\.net/i,
  /googleadservices\.com/i,
  /googlesyndication\.com/i,
  /s0\.2mdn\.net/i,
  /googlevideo\.com\/api\/stats\/ads/i,
  // 2024/2025 ad logging
  /jnn-pa\.googleapis\.com\/v1:logAdEvent/i,
  /jnn-pa\.googleapis\.com\/v1\/events:recordImpression/i,
  /jnn-pa\.googleapis\.com\/v1\/events:reportAdEvent/i,
  // Google ad measurement beacons
  /google\.com\/pagead\/adview/i,
  /google\.com\/pagead\/conversion/i,
  /google\.com\/pagead\/1p-user-list/i,
  /google\.com\/ccm\/collect/i,
];

// ── Google / auth UA fix ────────────────────────────────────────────────────
// Injected via executeJavaScript (runs in the page's MAIN world, NOT preload
// isolated world, and ignores CSP entirely). This overrides navigator.userAgentData
// so Google's sign-in never sees the real "Electron" brand, which triggers the
// "This browser may not be secure" error at the password step.
// Must run on EVERY navigation to google.com / accounts.google.com etc.
//
// KEY ANTI-DETECTION: Google's scripts use Function.prototype.toString() and
// Object.getOwnPropertyDescriptor() to detect if properties have been overridden
// with custom getters. We wrap both so our overrides appear native.
const GOOGLE_UA_FIX = `(function(){
  if(window._rbGoogleFix)return;
  window._rbGoogleFix=true;
  try{
    /* ── Step 0: Function.prototype.toString stealth ────────────────────────
       Google checks if getters are native by calling fn.toString() and looking
       for "[native code]". We wrap toString so all our custom getters report
       as native. This MUST happen before any _def calls. */
    var _fakeNatives=new WeakSet();
    var _origFnToStr=Function.prototype.toString;
    var _toStrProxy=function toString(){
      if(_fakeNatives.has(this))return'function '+((this.name||'')||'')+'() { [native code] }';
      return _origFnToStr.call(this);
    };
    _fakeNatives.add(_toStrProxy);
    Function.prototype.toString=_toStrProxy;
    /* Also protect Function.prototype.call/apply/bind.toString from revealing overrides */
    try{Object.defineProperty(Function.prototype,'toString',{writable:true,configurable:true});}catch(e){}

    /* ── Step 0b: Object.getOwnPropertyDescriptor stealth ──────────────────
       Google also uses Object.getOwnPropertyDescriptor(navigator, prop) to
       inspect property descriptors and detect custom getters. We intercept
       queries for key navigator properties and return native-looking descriptors. */
    var _origGOPD=Object.getOwnPropertyDescriptor;
    var _spoofedProps=new Map(); /* target -> Set of prop names */
    Object.getOwnPropertyDescriptor=function(obj,prop){
      var s=_spoofedProps.get(obj);
      if(s&&s.has(prop)){
        /* Return descriptor on Navigator.prototype instead — looks like the native one */
        var d=_origGOPD.call(Object,Object.getPrototypeOf(obj)||obj,prop);
        if(d)return d;
      }
      return _origGOPD.call(Object,obj,prop);
    };
    _fakeNatives.add(Object.getOwnPropertyDescriptor);

    var _UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36';
    var _br=[{brand:'Not_A Brand',version:'8'},{brand:'Chromium',version:'142'},{brand:'Google Chrome',version:'142'}];
    var _fvl=[{brand:'Not_A Brand',version:'8.0.0.0'},{brand:'Chromium',version:'142.0.7504.61'},{brand:'Google Chrome',version:'142.0.7504.61'}];
    var _aud={
      brands:_br, mobile:false, platform:'Windows',
      getHighEntropyValues:function getHighEntropyValues(hints){
        return Promise.resolve({architecture:'x86',bitness:'64',brands:_br,
          fullVersionList:_fvl,mobile:false,model:'',
          platform:'Windows',platformVersion:'10.0.0',uaFullVersion:'142.0.7504.61',
          wow64:false});
      },
      toJSON:function toJSON(){return {brands:_br,mobile:false,platform:'Windows'};}
    };
    _fakeNatives.add(_aud.getHighEntropyValues);
    _fakeNatives.add(_aud.toJSON);

    function _def(t,p,v){
      try{
        var g=function(){return v;};
        _fakeNatives.add(g);
        Object.defineProperty(t,p,{get:g,configurable:true});
        /* Track overridden props so GOPD can spoof them */
        if(!_spoofedProps.has(t))_spoofedProps.set(t,new Set());
        _spoofedProps.get(t).add(p);
      }catch(e){}
    }
    _def(navigator,'userAgentData',_aud);
    _def(navigator,'webdriver',false);
    _def(navigator,'userAgent',_UA);
    _def(navigator,'appVersion','5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36');
    _def(navigator,'vendor','Google Inc.');
    _def(navigator,'platform','Win32');
    _def(navigator,'language','en-US');
    _def(navigator,'languages',Object.freeze(['en-US','en']));
    _def(navigator,'hardwareConcurrency',8);
    _def(navigator,'pdfViewerEnabled',true);
    _def(navigator,'cookieEnabled',true);
    _def(navigator,'onLine',true);
    _def(navigator,'maxTouchPoints',0);
    _def(navigator,'appCodeName','Mozilla');
    _def(navigator,'appName','Netscape');
    _def(navigator,'product','Gecko');
    _def(navigator,'productSub','20030107');
    /* Plugins — Chrome always has PDF viewers; empty plugins is a strong signal */
    try{
      var _fp={name:'PDF Viewer',description:'Portable Document Format',filename:'internal-pdf-viewer',length:0};
      var _fp2={name:'Chrome PDF Viewer',description:'Portable Document Format',filename:'internal-pdf-viewer',length:0};
      var _fp3={name:'Chromium PDF Viewer',description:'Portable Document Format',filename:'internal-pdf-viewer',length:0};
      var _fp4={name:'Microsoft Edge PDF Viewer',description:'Portable Document Format',filename:'internal-pdf-viewer',length:0};
      var _fp5={name:'WebKit built-in PDF',description:'Portable Document Format',filename:'internal-pdf-viewer',length:0};
      var _fpl=Object.assign([_fp,_fp2,_fp3,_fp4,_fp5],{namedItem:function(n){return n.includes('PDF')?_fp:null;},item:function(i){return[_fp,_fp2,_fp3,_fp4,_fp5][i]||null;},refresh:function(){}});
      _def(navigator,'plugins',_fpl);
      var _mt=Object.assign([{type:'application/pdf',description:'PDF',enabledPlugin:_fp,suffixes:'pdf'}],{namedItem:function(t){return t==='application/pdf'?{}:null;},item:function(i){return i===0?{}:null;}});
      _def(navigator,'mimeTypes',_mt);
    }catch(e){}
    /* ── window.chrome — delete entirely and rebuild from scratch ───────────
       Electron sets its own chrome.runtime with Electron-specific properties
       (e.g. chrome.runtime.id pointing to internal extension). Assigning over
       it may silently fail if properties are non-configurable. Deleting the
       entire object and recreating it guarantees a clean Chrome-matching shape. */
    try{delete window.chrome;}catch(e){} try{window.chrome=undefined;}catch(e){}
    window.chrome={};
    window.chrome.app={isInstalled:false,InstallState:{DISABLED:'disabled',INSTALLED:'installed',NOT_INSTALLED:'not_installed'},RunningState:{CANNOT_RUN:'cannot_run',READY_TO_RUN:'ready_to_run',RUNNING:'running'},getDetails:function getDetails(){return null;},getIsInstalled:function getIsInstalled(){return false;},installState:function installState(cb){if(cb)cb('not_installed');},runningState:function runningState(){return'cannot_run';}};
    window.chrome.runtime={id:undefined,connect:function connect(){return{postMessage:function(){},onMessage:{addListener:function(){}},disconnect:function(){}};},sendMessage:function sendMessage(){},onMessage:{addListener:function(){}},onConnect:{addListener:function(){}},getPlatformInfo:function getPlatformInfo(cb){if(cb)cb({os:'win',arch:'x86-64',nacl_arch:'x86-64'});return Promise.resolve({os:'win',arch:'x86-64',nacl_arch:'x86-64'});},getManifest:function getManifest(){return undefined;},getURL:function getURL(){return'';},reload:function reload(){},requestUpdateCheck:function requestUpdateCheck(cb){if(cb)cb('no_update',{});}};
    window.chrome.csi=function csi(){return{startE:Date.now(),onloadT:Date.now(),pageT:1000,tran:15};};
    window.chrome.loadTimes=function loadTimes(){return{requestTime:Date.now()/1000,startLoadTime:Date.now()/1000,commitLoadTime:Date.now()/1000,finishDocumentLoadTime:Date.now()/1000,finishLoadTime:Date.now()/1000,firstPaintTime:Date.now()/1000,firstPaintAfterLoadTime:0,navigationType:'Other',wasFetchedViaSpdy:true,wasNpnNegotiated:true,npnNegotiatedProtocol:'h2',wasAlternateProtocolAvailable:false,connectionInfo:'h2'};};
    /* Mark chrome.app/runtime/csi/loadTimes as fake-native for toString checks */
    _fakeNatives.add(window.chrome.app.getDetails);_fakeNatives.add(window.chrome.app.getIsInstalled);
    _fakeNatives.add(window.chrome.app.installState);_fakeNatives.add(window.chrome.app.runningState);
    _fakeNatives.add(window.chrome.runtime.connect);_fakeNatives.add(window.chrome.runtime.sendMessage);
    _fakeNatives.add(window.chrome.runtime.getPlatformInfo);_fakeNatives.add(window.chrome.runtime.getManifest);
    _fakeNatives.add(window.chrome.runtime.getURL);_fakeNatives.add(window.chrome.runtime.reload);
    _fakeNatives.add(window.chrome.runtime.requestUpdateCheck);
    _fakeNatives.add(window.chrome.csi);_fakeNatives.add(window.chrome.loadTimes);
    /* Block WebAuthn/Passkeys — Google falls back to password entry.
       Keep PublicKeyCredential as a constructor but report no platform authenticator
       (setting to undefined is detectable since Chrome always has it). */
    try{
      var _oc=navigator.credentials;
      var _cg=function get(o){if(o&&o.publicKey)return Promise.reject(new DOMException('Not allowed','NotAllowedError'));return _oc?_oc.get.call(_oc,o):Promise.reject(new DOMException('Not allowed','NotAllowedError'));};
      var _cc=function create(o){if(o&&o.publicKey)return Promise.reject(new DOMException('Not allowed','NotAllowedError'));return _oc?_oc.create.call(_oc,o):Promise.reject(new DOMException('Not allowed','NotAllowedError'));};
      _fakeNatives.add(_cg);_fakeNatives.add(_cc);
      Object.defineProperty(navigator,'credentials',{get:function(){return{get:_cg,create:_cc,preventSilentAccess:function(){return Promise.resolve();},store:function(c){return _oc?_oc.store.call(_oc,c):Promise.resolve();}};},configurable:true});
    }catch(e){}
    try{
      if(typeof PublicKeyCredential!=='undefined'){
        var _pkc=function PublicKeyCredential(){throw new TypeError("Illegal constructor");};
        _pkc.isUserVerifyingPlatformAuthenticatorAvailable=function(){return Promise.resolve(false);};
        _pkc.isConditionalMediationAvailable=function(){return Promise.resolve(false);};
        _fakeNatives.add(_pkc);_fakeNatives.add(_pkc.isUserVerifyingPlatformAuthenticatorAvailable);_fakeNatives.add(_pkc.isConditionalMediationAvailable);
        Object.defineProperty(window,'PublicKeyCredential',{value:_pkc,configurable:true,writable:true});
      }
    }catch(e){}
    /* Headless detection: outerWidth/outerHeight === 0 in headless mode */
    try{
      var _ow=window.outerWidth||window.innerWidth||1280;
      var _oh=window.outerHeight||window.innerHeight||720;
      _def(window,'outerWidth',_ow);
      _def(window,'outerHeight',_oh);
    }catch(e){}
    try{
      _def(screen,'availWidth',screen.width||1920);
      _def(screen,'availHeight',screen.height||1080);
      _def(screen,'availLeft',0);
      _def(screen,'availTop',0);
    }catch(e){}
    /* Remove Electron-specific globals */
    try{delete window.Electron;}catch(e){}
    try{delete window.__electron;}catch(e){}
    try{delete window.__electronBinding;}catch(e){}
    try{if(window.process)delete window.process;}catch(e){}
    try{if(window.require)delete window.require;}catch(e){}
    try{if(window.module)delete window.module;}catch(e){}
    try{delete window.Buffer;}catch(e){}
    try{delete window.global;}catch(e){}
    try{delete window.__dirname;}catch(e){}
    try{delete window.__filename;}catch(e){}
    /* Remove non-Chrome browser identity signals */
    try{delete window.opr;}catch(e){}
    try{delete window.opera;}catch(e){}
    try{if(navigator.brave)_def(navigator,'brave',undefined);}catch(e){}
    try{if('globalPrivacyControl' in navigator)_def(navigator,'globalPrivacyControl',false);}catch(e){}
    /* Remove automation/testing globals */
    try{delete window.__nightmare;}catch(e){}
    try{delete window.callPhantom;}catch(e){}
    try{delete window._phantom;}catch(e){}
    try{delete window.domAutomation;}catch(e){}
    try{delete window.domAutomationController;}catch(e){}
    try{delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;}catch(e){}
    try{delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;}catch(e){}
    try{delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;}catch(e){}
    /* Remove Firefox/legacy signals */
    try{delete window.controllers;}catch(e){}
    try{delete window.Components;}catch(e){}
    try{delete window.mozInnerScreenX;}catch(e){}
    /* clientInformation alias */
    try{if(!window.clientInformation)_def(window,'clientInformation',navigator);}catch(e){}
    /* document.hasFocus() */
    try{var _hf=function hasFocus(){return true;};_fakeNatives.add(_hf);Object.defineProperty(document,'hasFocus',{value:_hf,configurable:true,writable:true});}catch(e){}
    /* navigator.connection */
    try{if(!navigator.connection)_def(navigator,'connection',{effectiveType:'4g',rtt:50,downlink:10,saveData:false,addEventListener:function(){},removeEventListener:function(){}});}catch(e){}
    /* speechSynthesis voices */
    try{if(window.speechSynthesis){var _origGV=window.speechSynthesis.getVoices.bind(window.speechSynthesis);var _fv=[{voiceURI:'Google US English',name:'Google US English',lang:'en-US',localService:true,default:true},{voiceURI:'Google UK English Female',name:'Google UK English Female',lang:'en-GB',localService:false,default:false}];var _gvFn=function getVoices(){var r=_origGV();return(r&&r.length)?r:_fv;};_fakeNatives.add(_gvFn);window.speechSynthesis.getVoices=_gvFn;}}catch(e){}
    /* Notification.permission */
    try{if(typeof Notification!=='undefined')Object.defineProperty(Notification,'permission',{get:function(){return'default';},configurable:true});}catch(e){}
    /* Permission API — return 'prompt' for all permission queries (matches fresh Chrome install) */
    try{if(navigator.permissions){var _origQ=navigator.permissions.query.bind(navigator.permissions);var _pqFn=function query(desc){if(desc&&(desc.name==='notifications'||desc.name==='push'))return Promise.resolve({state:'prompt',status:'prompt',onchange:null});return _origQ(desc);};_fakeNatives.add(_pqFn);navigator.permissions.query=_pqFn;}}catch(e){}
    /* Block service worker registration — SW context doesn't get our overrides,
       so Google's SW could report real Electron identity back to the server. */
    try{if(navigator.serviceWorker){var _origReg=navigator.serviceWorker.register.bind(navigator.serviceWorker);var _srFn=function register(){return Promise.reject(new DOMException('Failed to register a ServiceWorker','SecurityError'));};_fakeNatives.add(_srFn);navigator.serviceWorker.register=_srFn;}}catch(e){}
  }catch(e){}
})();
`;
const _GOOGLE_RE = /google\.com|googleapis\.com|gstatic\.com|gmail\.com|youtube\.com/i;
function _injectGoogleUAFix(wc) {
  if (!wc || wc.isDestroyed()) return;
  try {
    const url = wc.getURL();
    if (url && _GOOGLE_RE.test(url)) {
      wc.executeJavaScript(GOOGLE_UA_FIX).catch(() => {});
    }
  } catch {}
}

// ── Video PiP — injected into every BV page ──────────────────────────────────
// Button appears at the TOP-RIGHT corner of the video element itself.
// Shows on hover (YouTube / any site) and on autoplay without hover (TikTok).
// Real in-page click → requestPictureInPicture works everywhere.
const VIDEO_PIP_INJECT = `(function(){
  // Cleanup any prior instance — disconnects observers and clears intervals
  // to prevent accumulation on SPA navigations (especially YouTube Shorts).
  if(window._rawPipCleanup){try{window._rawPipCleanup();}catch(e){}}
  if(window._rawPipV3)return;
  window._rawPipV3=true;
  // Remove any stale button from a previous injection to prevent duplicates on TikTok SPA navigation
  var _staleBtn=document.getElementById('_rawPipBtn');if(_staleBtn)_staleBtn.remove();

  /* ── Floating PiP button — positioned over video top-right ── */
  var btn=document.createElement('button');
  btn.id='_rawPipBtn';
  btn.style.cssText=
    'position:fixed;z-index:2147483640;top:12px;right:12px;'+
    'background:rgba(0,0,0,.72);color:#fff;'+
    'border:none;border-radius:7px;'+
    'padding:6px 12px 6px 9px;font:600 11px/1.2 -apple-system,sans-serif;'+
    'cursor:pointer;display:flex;align-items:center;gap:5px;'+
    'backdrop-filter:blur(10px);white-space:nowrap;'+
    'box-shadow:0 2px 12px rgba(0,0,0,.65);'+
    'opacity:0;pointer-events:none;'+
    'transition:opacity .16s;';
  btn.innerHTML=
    '<svg width="12" height="12" viewBox="0 0 14 14" fill="none" style="flex-shrink:0">'+
    '<rect x="1" y="2" width="12" height="9" rx="1.5" stroke="currentColor" stroke-width="1.3"/>'+
    '<rect x="6.5" y="6" width="5.5" height="4" rx="1" fill="currentColor" opacity=".75"/>'+
    '</svg><span id="_rawPipLbl">Pop Out</span>';
  document.documentElement.appendChild(btn);

  var _pip=false, _activeV=null, _hideTimer=null, _ro=null;
  var _isTikTok = /tiktok\.com/i.test(location.hostname);

  /* ── Position button at top-right of a video element ── */
  /* On TikTok: bottom-left to avoid blocking the scroll-to-next-video arrow */
  function _pos(v){
    if(!v)return;
    var r=v.getBoundingClientRect();
    var bw=btn.offsetWidth||90;
    if(_isTikTok){
      btn.style.top='auto';
      btn.style.bottom=Math.max(8, window.innerHeight-r.bottom+8)+'px';
      btn.style.left=Math.max(8, r.left+8)+'px';
      btn.style.right='auto';
    }else{
      btn.style.top=Math.max(8,r.top+8)+'px';
      btn.style.left=Math.max(0,r.right-bw-8)+'px';
      btn.style.right='auto';
      btn.style.bottom='auto';
    }
  }

  function _show(v){
    clearTimeout(_hideTimer);
    if(v)_activeV=v;
    if(_activeV)_pos(_activeV);
    btn.style.opacity='1';
    btn.style.pointerEvents='all';
  }
  function _hide(delay){
    clearTimeout(_hideTimer);
    _hideTimer=setTimeout(function(){
      btn.style.opacity='0';
      btn.style.pointerEvents='none';
    },delay||0);
  }

  /* Reposition when user scrolls/resizes (keeps button glued to video) */
  function _repos(){
    if(btn.style.opacity==='1'&&_activeV){ _pos(_activeV); }
  }
  window.addEventListener('scroll',_repos,{passive:true,capture:true});
  window.addEventListener('resize',_repos,{passive:true});

  /* ── Bind hover events directly to a video element ── */
  function _bindVideo(v){
    if(v._rawPipBound)return;
    v._rawPipBound=true;
    v.addEventListener('mouseenter',function(){_show(v);},true);
    v.addEventListener('mouseleave',function(e){
      /* Don't hide if mouse moved onto the button */
      if(!_pip&&e.relatedTarget!==btn)_hide(550);
    },true);
    /* Track video resize/position changes so button stays glued to the video */
    if(typeof ResizeObserver!=='undefined'){
      if(_ro)_ro.disconnect();
      _ro=new ResizeObserver(function(){ if(btn.style.opacity==='1'&&_activeV)_pos(_activeV); });
      _ro.observe(v);
    }
  }
  function _bindAll(){
    document.querySelectorAll('video').forEach(_bindVideo);
  }
  _bindAll();

  /* Watch for videos added dynamically (TikTok / YouTube SPA) */
  var _mo=new MutationObserver(function(muts){
    for(var i=0;i<muts.length;i++){
      if(muts[i].addedNodes&&muts[i].addedNodes.length){ _bindAll(); break; }
    }
  });
  _mo.observe(document.body||document.documentElement,{childList:true,subtree:true});

  /* ── Also poll for autoplay videos the hover approach can't catch ── */
  /* (TikTok: video plays full-screen without the user hovering)       */
  function _bestPlaying(){
    var vw=window.innerWidth,vh=window.innerHeight,best=null,score=-1;
    document.querySelectorAll('video').forEach(function(v){
      if(v.paused||v.ended)return;
      if(v.readyState<2&&v.videoWidth<1)return;
      var r=v.getBoundingClientRect();
      if(r.width<60||r.height<40)return;
      if(r.right<=0||r.bottom<=0||r.left>=vw||r.top>=vh)return;
      var s=(v.duration||0)*6+(r.width*r.height/6000);
      if(s>score){score=s;best=v;}
    });
    return best;
  }
  function _poll(){
    if(_pip){_show();return;}
    var v=_bestPlaying();
    if(v){ _bindVideo(v); _show(v); }
    /* Don't auto-hide — let mouseleave / _hide handle it */
  }

  /* ── Video play/pause events ── */
  document.addEventListener('play',function(e){
    if(e.target&&e.target.tagName==='VIDEO'){ _bindVideo(e.target); _poll(); }
  },true);
  document.addEventListener('pause',function(e){
    if(e.target&&e.target.tagName==='VIDEO'&&e.target===_activeV){
      if(!_pip) _hide(800);
    }
  },true);

  /* ── PiP state tracking ── */
  document.addEventListener('enterpictureinpicture',function(){
    _pip=true;
    var lbl=document.getElementById('_rawPipLbl');
    if(lbl)lbl.textContent='Exit PiP';
    _show();
  });
  document.addEventListener('leavepictureinpicture',function(){
    _pip=false;
    var lbl=document.getElementById('_rawPipLbl');
    if(lbl)lbl.textContent='Pop Out';
    _hide(700);
  });

  /* Keep button visible when mouse is on it */
  btn.addEventListener('mouseenter',function(){ clearTimeout(_hideTimer); });
  btn.addEventListener('mouseleave',function(e){
    if(!_pip&&e.relatedTarget!==_activeV) _hide(300);
  });

  /* ── Click: enter or exit PiP ── */
  btn.addEventListener('click',function(e){
    e.stopPropagation(); e.preventDefault();
    if(document.pictureInPictureElement){
      document.exitPictureInPicture().catch(function(){});
    }else{
      var v=_activeV||_bestPlaying()||
            document.querySelector('#movie_player video')||
            document.querySelector('.html5-video-player video')||
            document.querySelector('video');
      if(!v)return;
      try{v.disablePictureInPicture=false;}catch(x){}
      v.requestPictureInPicture().catch(function(err){
        console.warn('[RAW PiP]',err.message);
      });
    }
  });

  /* ── Initial poll + recurring poll for autoplay sites ── */
  var _polled=0, _slowIv=null;
  var _fastIv=setInterval(function(){
    _poll(); _polled++;
    if(_polled>=60){ clearInterval(_fastIv); _slowIv=setInterval(_poll,4000); }
  },1000);
  _poll();

  /* ── Cleanup function — called on re-injection to prevent observer/interval accumulation ── */
  window._rawPipCleanup=function(){
    try{_mo.disconnect();}catch(e){}
    try{clearInterval(_fastIv);}catch(e){}
    if(_slowIv)try{clearInterval(_slowIv);}catch(e){}
    if(_ro)try{_ro.disconnect();}catch(e){}
    window.removeEventListener('scroll',_repos,{capture:true});
    window.removeEventListener('resize',_repos);
    window._rawPipV3=false;
    window._rawPipCleanup=null;
  };
})();`;

// ── Extension content scripts (injected into BrowserView via executeJavaScript) ─
const EXT_SCRIPTS = {
  'dark-mode':
    `(function(){
      if(document.getElementById('_rawDark'))return;
      /* Step 1: Set color-scheme so native inputs render dark */
      var s=document.createElement('style');s.id='_rawDark';
      s.textContent=':root{color-scheme:dark!important;}'+
        '::selection{background:rgba(0,180,160,.5)!important;}';
      document.head.appendChild(s);

      /* Step 2: Smart invert — only on light pages.
         Checks actual computed background of html/body (falls back through
         transparency chain), respects declared color-scheme:dark, and
         skips sites that already have a dark-mode class on <html>/<body>.
         SVG inline elements are re-inverted so icons stay natural. */
      function _applyInvert(){
        if(document.getElementById('_rawDarkInv'))return;
        /* Check if site natively declared dark color-scheme */
        try {
          var cs = getComputedStyle(document.documentElement).colorScheme || '';
          if(cs.includes('dark')) return;
        } catch(e){}
        /* Check for common dark-mode class names on root/body */
        var rootCls = (document.documentElement.className||'')+' '+((document.body||{}).className||'');
        if(/\b(dark|dark-mode|dark-theme|dark-layout|night|black-theme)\b/i.test(rootCls)) return;
        /* Find real background — walk up from body through transparent layers */
        var el=document.body||document.documentElement;
        var bg=getComputedStyle(el).backgroundColor;
        if(bg==='rgba(0, 0, 0, 0)'||bg==='transparent'){
          bg=getComputedStyle(document.documentElement).backgroundColor;
        }
        var m=bg.match(/\\d+/g);
        /* If still transparent or unreadable, assume light (invert) */
        var lum=m&&m.length>=3?(+m[0]*299+(+m[1])*587+(+m[2])*114)/1000:210;
        if(lum<90) return; /* page is already dark — skip */
        var si=document.createElement('style');si.id='_rawDarkInv';
        /* Apply filter to body. SVG added to re-invert list so inline icons
           stay natural. iframe excluded — compositor layer conflict in Electron. */
        si.textContent='body{filter:invert(1) hue-rotate(180deg)!important;}'+
          'img,video,canvas,picture,embed,object,svg,'+
          '[style*="background-image"],[style*="background:url"],[style*="background: url"]'+
          '{filter:invert(1) hue-rotate(180deg)!important}';
        document.head.appendChild(si);
      }
      if(document.readyState==='complete'){_applyInvert();}
      else{window.addEventListener('load',function(){setTimeout(_applyInvert,600);});}
      /* Also run after a 900ms delay so JS-powered dark themes have time to apply */
      setTimeout(_applyInvert,900);
    })()`,
  'no-animations':
    `(function(){if(document.getElementById('_rawNoAnim'))return;var s=document.createElement('style');s.id='_rawNoAnim';s.textContent='*,*::before,*::after{animation:none!important;transition:none!important;}';document.head.appendChild(s);})()`,
  'video-speed':
    `(function(){if(window._rawSpeedUI)return;var el=document.createElement('div');el.id='_rawSpeed';el.style.cssText='position:fixed;bottom:20px;right:20px;z-index:2147483647;background:rgba(0,0,0,.85);color:#00d4c8;font:bold 13px/1 -apple-system,sans-serif;padding:7px 14px;border-radius:8px;cursor:pointer;user-select:none;border:1px solid rgba(0,212,200,.4);';var spd=1;function upd(){el.textContent='\u23e9 '+spd.toFixed(2)+'\u00d7';document.querySelectorAll('video').forEach(function(v){v.playbackRate=spd;});}el.onclick=function(e){e.stopPropagation();spd=spd>=3?0.25:+(spd+0.25).toFixed(2);upd();};document.body.appendChild(el);window._rawSpeedUI=el;upd();})()`,
  'focus-mode':
    `(function(){if(document.getElementById('_rawFocus'))return;var s=document.createElement('style');s.id='_rawFocus';s.textContent='header,nav,footer,aside,[class*="sidebar"],[class*="widget"],[class*="banner"],[class*="promo"],[class*="recommend"],[class*="related"],[id*="sidebar"],[id*="nav"]{opacity:.08!important;pointer-events:none!important;}main,article,[role="main"],[class*="article-body"],[class*="post-content"],[class*="entry-content"]{max-width:700px!important;margin:0 auto!important;padding:0 24px!important;}';document.head.appendChild(s);})()`,
  'grayscale':
    `(function(){if(document.getElementById('_rawGray'))return;var s=document.createElement('style');s.id='_rawGray';s.textContent='html{filter:grayscale(1)!important;}';document.head.appendChild(s);})()`,
  'night-filter':
    `(function(){if(document.getElementById('_rawNight'))return;var d=document.createElement('div');d.id='_rawNight';d.style.cssText='position:fixed;inset:0;background:rgba(255,130,0,.18);pointer-events:none;z-index:2147483646;';document.documentElement.appendChild(d);})()`,
  'highlight-links':
    `(function(){if(document.getElementById('_rawLinks'))return;var s=document.createElement('style');s.id='_rawLinks';s.textContent='a{text-decoration-line:underline!important;text-decoration-color:rgba(0,212,200,.55)!important;text-underline-offset:2px!important;}';document.head.appendChild(s);})()`,
  'scroll-progress':
    `(function(){if(document.getElementById('_rawScProg'))return;var b=document.createElement('div');b.id='_rawScProg';b.style.cssText='position:fixed;top:0;left:0;height:3px;width:0%;background:linear-gradient(90deg,#00d4c8,#00bdb0);z-index:2147483646;transition:width .08s linear;pointer-events:none';document.documentElement.appendChild(b);function _upd(){var s=document.documentElement;var p=s.scrollTop/(s.scrollHeight-s.clientHeight)*100;b.style.width=Math.min(100,isNaN(p)?0:p)+'%';}window.addEventListener('scroll',_upd,{passive:true});})()`,
  'font-boost':
    `(function(){if(document.getElementById('_rawFont'))return;var s=document.createElement('style');s.id='_rawFont';s.textContent='body,p,li,td,th,article,section,main{font-size:108%!important;line-height:1.75!important;}';document.head.appendChild(s);})()`,
  'reader-mode':
    `(function(){if(document.getElementById('_rawReader'))return;var s=document.createElement('style');s.id='_rawReader';s.textContent='body,article,main,section{max-width:740px!important;margin:0 auto!important;padding:32px 28px!important;font-size:18px!important;line-height:1.9!important;background:#111!important;color:#d8d8d8!important;font-family:Georgia,serif!important;}h1,h2,h3,h4,h5,h6{color:#f0f0f0!important;line-height:1.3!important;margin:1.4em 0 .5em!important;}a{color:#00d4c8!important;}p,li{color:#d0d0d0!important;}img,video,picture,figure,iframe,canvas,svg[width][height],embed,object,.image,[class*="image"],[class*="photo"],[class*="media"],[class*="gallery"][class*="caption"]{display:none!important;}nav,header,footer,aside,[role="banner"],[role="navigation"],[role="complementary"],[class*="sidebar"],[id*="sidebar"],[class*="nav"],[id*="nav"],[class*="header"],[id*="header"],[class*="footer"],[id*="footer"],[class*="related"],[class*="recommend"],[class*="ad-"],[id*="-ad"],[class*="ad_"],[class*="advert"],[class*="banner"],[class*="popup"],[class*="modal"],[class*="cookie"],[class*="toolbar"],[class*="social"],[class*="share"]{display:none!important;}';document.head.appendChild(s);})()`,
  'image-zoom':
    `(function(){if(window._rawImgZoom)return;window._rawImgZoom=true;var ov=document.createElement('div');ov.id='_rawImgZoomOv';ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:2147483647;display:none;align-items:center;justify-content:center;cursor:zoom-out;backdrop-filter:blur(6px)';var im=document.createElement('img');im.style.cssText='max-width:92vw;max-height:92vh;border-radius:6px;box-shadow:0 4px 60px rgba(0,0,0,.9)';ov.appendChild(im);document.documentElement.appendChild(ov);ov.addEventListener('click',function(){ov.style.display='none';});document.addEventListener('click',function(e){if(e.target.tagName==='IMG'&&e.target.naturalWidth>200){im.src=e.target.src;ov.style.display='flex';}});})()`,
  'word-count':
    `(function(){if(document.getElementById('_rawWordCnt'))return;var w=(document.body.innerText||'').trim().split(/\s+/).filter(Boolean).length;var m=Math.max(1,Math.round(w/200));var b=document.createElement('div');b.id='_rawWordCnt';b.style.cssText='position:fixed;bottom:18px;right:18px;background:rgba(10,10,10,.82);color:#aaa;font-size:11.5px;padding:5px 12px;border-radius:20px;z-index:2147483646;pointer-events:none;backdrop-filter:blur(10px);font-family:system-ui,sans-serif;letter-spacing:.02em;border:1px solid rgba(255,255,255,.08)';b.textContent=w.toLocaleString()+' words · '+m+' min read';document.documentElement.appendChild(b);})()`,
  'anti-tracking':
    `(function(){if(document.getElementById('_rawAntiTrk'))return;var s=document.createElement('style');s.id='_rawAntiTrk';s.textContent='img[width="1"],img[height="1"],img[width="0"],img[height="0"],img[style*="display:none"],img[style*="display: none"]{display:none!important;visibility:hidden!important;}';document.head.appendChild(s);})()`,
  'print-clean':
    `(function(){if(document.getElementById('_rawPrint'))return;var s=document.createElement('style');s.id='_rawPrint';s.textContent='@media print{nav,header,footer,aside,iframe,[class*="ad"],[id*="ad"],[class*="banner"],[class*="sidebar"],[class*="popup"],[class*="cookie"],[class*="social"],[class*="share"],[class*="related"]{display:none!important}body{font-size:11pt!important;line-height:1.6!important;color:#000!important;background:#fff!important}a::after{content:" ("attr(href)")";}img{max-width:100%!important}}';document.head.appendChild(s);})()`,
  'smooth-scroll':
    `(function(){if(document.getElementById('_rawSmooth'))return;var s=document.createElement('style');s.id='_rawSmooth';s.textContent='html{scroll-behavior:smooth!important;}';document.head.appendChild(s);})()`,
  'smart-copy':
    `(function(){if(window._rawSmartCopy)return;window._rawSmartCopy=true;document.addEventListener('copy',function(e){var sel=window.getSelection();if(!sel||!sel.toString())return;e.preventDefault();e.clipboardData.setData('text/plain',sel.toString());},true);})()`,
  'hide-comments':
    `(function(){if(document.getElementById('_rawHideCom'))return;var s=document.createElement('style');s.id='_rawHideCom';s.textContent='[id*="comment" i],[class*="comment" i],[id*="disqus"],[class*="disqus"],[id*="discuss" i],[class*="discuss" i],[id*="replies" i],[class*="replies" i]{display:none!important;}';document.head.appendChild(s);})()`,
  'link-preview':
    `(function(){if(window._rawLinkPrev)return;window._rawLinkPrev=true;var tip=document.createElement('div');tip.id='_rawLinkPrev';tip.style.cssText='position:fixed;bottom:12px;left:50%;transform:translateX(-50%);max-width:520px;background:rgba(12,12,12,.92);color:#a0a0a0;font:12px/1.4 system-ui,sans-serif;padding:4px 14px;border-radius:7px;z-index:2147483646;pointer-events:none;opacity:0;transition:opacity .15s;backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,.1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;';document.documentElement.appendChild(tip);document.addEventListener('mouseover',function(e){var a=e.target.closest('a');if(a&&a.href&&!/^javascript/i.test(a.href)){tip.textContent=a.href;tip.style.opacity='1';}});document.addEventListener('mouseout',function(e){if(e.target.closest('a'))tip.style.opacity='0';});})()`,
  'custom-cursor':
    `(function(){if(window._rawCursor)return;window._rawCursor=true;var cs=document.createElement('style');cs.id='_rawCursorCSS';cs.textContent='html{cursor:none!important}a,button,[role="button"],[onclick]{cursor:none!important}input,textarea,[contenteditable]{cursor:auto!important}';(document.head||document.documentElement).appendChild(cs);var tr=document.createElement('div');tr.id='_rawCursorRing';tr.style.cssText='position:fixed;width:18px;height:18px;border-radius:50%;border:2px solid #00d4c8;pointer-events:none;z-index:2147483647;transform:translate(-50%,-50%);top:-200px;left:-200px;box-shadow:0 0 10px rgba(0,212,200,.6),0 0 20px rgba(0,212,200,.2);background:rgba(0,212,200,.06);will-change:transform;';document.documentElement.appendChild(tr);var rx=-200,ry=-200;function onMove(e){rx=e.clientX;ry=e.clientY;tr.style.left=rx+'px';tr.style.top=ry+'px';}document.addEventListener('mousemove',onMove,{passive:true});document.addEventListener('mouseleave',function(){tr.style.opacity='0';});document.addEventListener('mouseenter',function(){tr.style.opacity='1';});})()`,
  'auto-scroll':
    `(function(){if(window._rawAutoScrollBtn)return;var spd=0,anim,btn=document.createElement('div');btn.id='_rawAutoScrollBtn';btn.style.cssText='position:fixed;bottom:60px;right:20px;z-index:2147483647;background:rgba(0,0,0,.85);color:#00d4c8;font:bold 12px/1 system-ui;padding:6px 14px;border-radius:8px;cursor:pointer;user-select:none;border:1px solid rgba(0,212,200,.4);';btn.textContent='\u25bc Auto';window._rawAutoScrollBtn=btn;function tick(){if(spd>0){window.scrollBy(0,spd);anim=requestAnimationFrame(tick);}}btn.onclick=function(e){e.stopPropagation();spd=spd>0?0:1.5;btn.textContent=spd>0?'\u25a0 Stop':'\u25bc Auto';if(spd>0)anim=requestAnimationFrame(tick);else if(anim)cancelAnimationFrame(anim);};document.body.appendChild(btn);})()`,
  'high-contrast':
    `(function(){if(document.getElementById('_rawHiCon'))return;var s=document.createElement('style');s.id='_rawHiCon';s.textContent='html{filter:contrast(1.65)!important;}';document.head.appendChild(s);})()`,
  'pip-mode':
    // Trigger PiP via the floating button injected by VIDEO_PIP_INJECT — it has a
    // real user-gesture context from the click event (IPC-direct requestPiP fails).
    `(function(){
      window._rawPip=true;
      // If VIDEO_PIP_INJECT button is already in the page, use it (has user gesture)
      var btn=document.getElementById('_rawPipBtn');
      if(btn){
        var ev=new MouseEvent('click',{bubbles:true,cancelable:true,view:window});
        btn.dispatchEvent(ev);
        return;
      }
      // Fallback: find best visible video and attempt PiP (may need a real user gesture
      // but works on pages that allow autoplay with permissions policy)
      var vw=window.innerWidth,vh=window.innerHeight;
      var best=null,bestScore=-1;
      document.querySelectorAll('video').forEach(function(v){
        var r=v.getBoundingClientRect();
        if(r.width<80||r.height<50)return;
        var score=(v.paused?0:3000)+(v.duration||0)*10+(r.width*r.height/1e4);
        if(score>bestScore){bestScore=score;best=v;}
      });
      if(!best)best=document.querySelector('#movie_player video')||document.querySelector('video');
      if(best){
        try{best.disablePictureInPicture=false;}catch(e){}
        best.requestPictureInPicture().catch(function(err){
          console.warn('[RAW pip-mode]',err.message,'— hover the video and use the Pop Out button');
        });
      }
    })()`,
  'sticky-notes':
    `(function(){if(window._rawStickyNotes)return;window._rawStickyNotes=true;var d=document.createElement('div');d.id='_rawStickyNotes';d.style.cssText='position:fixed;bottom:80px;right:20px;z-index:2147483647;width:230px;background:rgba(10,10,10,.97);border-radius:12px;border:1px solid rgba(0,212,200,.3);box-shadow:0 4px 24px rgba(0,0,0,.6);overflow:hidden;font-family:system-ui,sans-serif;';var hdr=document.createElement('div');hdr.style.cssText='padding:8px 12px;background:rgba(0,212,200,.1);font-size:11px;font-weight:700;color:#00d4c8;cursor:move;display:flex;align-items:center;justify-content:space-between;user-select:none;';hdr.innerHTML='<span>\u{1F4DD} STICKY NOTE</span>';var cls=document.createElement('button');cls.textContent='\u00d7';cls.style.cssText='background:none;border:none;color:#666;font-size:16px;cursor:pointer;padding:0 2px;line-height:1;';cls.onclick=function(){d.remove();window._rawStickyNotes=false;};hdr.appendChild(cls);var ta=document.createElement('textarea');ta.style.cssText='width:100%;height:110px;background:transparent;border:none;border-top:1px solid rgba(255,255,255,.07);padding:10px 12px;color:#ccc;font-size:12px;resize:vertical;outline:none;box-sizing:border-box;font-family:inherit;line-height:1.5;';ta.placeholder='Type notes\u2026';d.appendChild(hdr);d.appendChild(ta);document.documentElement.appendChild(d);var mx=0,my=0,drag=false;hdr.addEventListener('mousedown',function(e){drag=true;mx=e.clientX-d.offsetLeft;my=e.clientY-d.offsetTop;});document.addEventListener('mousemove',function(e){if(!drag)return;d.style.right='auto';d.style.bottom='auto';d.style.left=(e.clientX-mx)+'px';d.style.top=(e.clientY-my)+'px';});document.addEventListener('mouseup',function(){drag=false;});})()`,
  'low-data':
    `(function(){if(document.getElementById('_rawLowData'))return;var s=document.createElement('style');s.id='_rawLowData';s.textContent='img,picture,svg image{visibility:hidden!important;}video,iframe[src*="youtube"],iframe[src*="vimeo"]{display:none!important;}';document.head.appendChild(s);var b=document.createElement('div');b.id='_rawLowDataBadge';b.style.cssText='position:fixed;top:10px;right:10px;z-index:2147483646;background:rgba(10,10,10,.9);color:#f0c030;font:700 10px/1 system-ui;padding:4px 10px;border-radius:6px;border:1px solid rgba(240,192,48,.3);pointer-events:none;letter-spacing:.06em;';b.textContent='LOW DATA MODE';document.documentElement.appendChild(b);})()`,
  'neon-glow':
    `(function(){if(document.getElementById('_rawNeonGlow'))return;var s=document.createElement('style');s.id='_rawNeonGlow';s.textContent='h1,h2,h3{text-shadow:0 0 14px rgba(0,212,200,.55),0 0 32px rgba(0,212,200,.2)!important;color:#e0fffe!important;}a:hover{text-shadow:0 0 8px rgba(0,212,200,.65)!important;color:#00ffec!important;}button,input[type="submit"]{box-shadow:0 0 10px rgba(0,212,200,.35),0 0 22px rgba(0,212,200,.12)!important;}';document.head.appendChild(s);})()`,
  'page-zoom':
    `(function(){if(window._rawZoomCtrl)return;window._rawZoomCtrl=true;var lvl=1;var wrap=document.createElement('div');wrap.id='_rawZoomCtrl';wrap.style.cssText='position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:2147483647;display:flex;align-items:center;gap:6px;background:rgba(10,10,10,.92);border:1px solid rgba(0,212,200,.28);border-radius:10px;padding:5px 10px;font-family:system-ui;box-shadow:0 4px 16px rgba(0,0,0,.5);';function _btn(t){var b=document.createElement('button');b.textContent=t;b.style.cssText='background:rgba(0,212,200,.12);border:1px solid rgba(0,212,200,.25);color:#00d4c8;font-size:14px;font-weight:700;width:26px;height:26px;border-radius:6px;cursor:pointer;';return b;}var bM=_btn('-'),lbl=document.createElement('span'),bP=_btn('+'),bR=_btn('\u21ba');lbl.style.cssText='color:#ccc;font-size:11px;font-weight:600;min-width:38px;text-align:center;';lbl.textContent='100%';function _sz(z){lvl=Math.min(3,Math.max(0.3,z));document.body.style.zoom=lvl;lbl.textContent=Math.round(lvl*100)+'%';}bM.onclick=function(){_sz(+(lvl-0.1).toFixed(1));};bP.onclick=function(){_sz(+(lvl+0.1).toFixed(1));};bR.onclick=function(){_sz(1);};[bM,lbl,bP,bR].forEach(function(el){wrap.appendChild(el);});document.documentElement.appendChild(wrap);})()`,
  // YouTube Ad Skipper — enabled as an add-on, not automatically
  'yt-ad': YT_AD_SKIP,
  'serif-mode':
    `(function(){if(document.getElementById('_rawSerif'))return;var s=document.createElement('style');s.id='_rawSerif';s.textContent='body,p,li,td,th,article,section,main,blockquote{font-family:Georgia,"Times New Roman",Times,serif!important;}';document.head.appendChild(s);})()`,
  'scroll-top':
    `(function(){if(window._rawScrollTop)return;window._rawScrollTop=true;var b=document.createElement('button');b.id='_rawScrollTopBtn';b.style.cssText='position:fixed;bottom:26px;right:26px;z-index:2147483647;width:38px;height:38px;border-radius:50%;background:rgba(0,0,0,.82);border:1.5px solid rgba(0,212,200,.4);color:#00d4c8;cursor:pointer;display:none;align-items:center;justify-content:center;transition:opacity .2s,background .15s;box-shadow:0 4px 14px rgba(0,0,0,.5);backdrop-filter:blur(8px);';b.innerHTML='<svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 8l4-4 4 4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';b.onclick=function(){window.scrollTo({top:0,behavior:'smooth'});};window.addEventListener('scroll',function(){b.style.display=window.scrollY>300?'flex':'none';},{passive:true});b.addEventListener('mouseenter',function(){b.style.background='rgba(0,212,200,.15)';});b.addEventListener('mouseleave',function(){b.style.background='rgba(0,0,0,.82)';});document.documentElement.appendChild(b);})()`,
  'code-highlight':
    `(function(){if(document.getElementById('_rawCode'))return;var s=document.createElement('style');s.id='_rawCode';s.textContent='pre,code,kbd,samp{background:rgba(0,212,200,.07)!important;border:1px solid rgba(0,212,200,.18)!important;border-radius:5px!important;font-family:"Fira Code","Cascadia Code","Courier New",monospace!important;color:#7dd9d4!important;padding:.15em .4em!important;}pre code{background:transparent!important;border:none!important;padding:0!important;}pre{padding:12px 16px!important;overflow-x:auto!important;line-height:1.6!important;}';document.head.appendChild(s);})()`,
  'url-cleaner':
    `(function(){if(window._rawUrlClean)return;window._rawUrlClean=true;var P=['utm_source','utm_medium','utm_campaign','utm_term','utm_content','utm_id','fbclid','gclid','gclsrc','msclkid','mc_eid','ref','referrer','source','_ga','_gl','igshid','twclid','yclid','zanpid','dclid','s_cid','mc_cid','mkt_tok','trk','trkCampaign','trkInfo'];function _clean(){try{var u=new URL(location.href);var ch=false;P.forEach(function(p){if(u.searchParams.has(p)){u.searchParams.delete(p);ch=true;}});if(ch)history.replaceState(null,'',u.toString());}catch(e){}}if(document.readyState==='complete')_clean();else window.addEventListener('load',_clean,{once:true});})()`,
  'distraction-block':
    `(function(){if(document.getElementById('_rawDistract'))return;var s=document.createElement('style');s.id='_rawDistract';s.textContent='[class*="cookie" i],[id*="cookie" i],[class*="gdpr" i],[id*="gdpr" i],[class*="consent" i]:not(main):not(article),[class*="banner" i]:not(header):not(nav),[class*="newsletter" i],[id*="newsletter" i],[class*="subscribe" i]:not(input):not(button),[class*="popup" i]:not(main),[class*="modal" i]:not([role="dialog"]):not([aria-modal]),[class*="interstitial" i],[class*="paywall" i],[id*="paywall" i],[data-testid*="cookie" i],[data-testid*="consent" i],[aria-label*="cookie" i],[aria-label*="newsletter" i],[class*="overlay" i]:not(main):not([role="main"]){display:none!important;visibility:hidden!important;opacity:0!important;pointer-events:none!important;}body{overflow:auto!important;}';document.head.appendChild(s);})()`,
};

const EXT_UNSCRIPTS = {
  'dark-mode':       `(function(){['_rawDark','_rawDarkInv'].forEach(function(id){var e=document.getElementById(id);if(e)e.remove();});})()`,
  'no-animations':   `(function(){var s=document.getElementById('_rawNoAnim');if(s)s.remove();})()`,
  'video-speed':     `(function(){var el=document.getElementById('_rawSpeed');if(el)el.remove();delete window._rawSpeedUI;})()`,
  'focus-mode':      `(function(){var s=document.getElementById('_rawFocus');if(s)s.remove();})()`,
  'grayscale':       `(function(){var s=document.getElementById('_rawGray');if(s)s.remove();})()`,
  'night-filter':    `(function(){var el=document.getElementById('_rawNight');if(el)el.remove();})()`,
  'highlight-links':  `(function(){var s=document.getElementById('_rawLinks');if(s)s.remove();})()`, 
  'scroll-progress':  `(function(){document.getElementById('_rawScProg')?.remove();})()`,
  'font-boost':       `(function(){document.getElementById('_rawFont')?.remove();})()`,
  'reader-mode':      `(function(){document.getElementById('_rawReader')?.remove();})()`,
  'image-zoom':       `(function(){document.getElementById('_rawImgZoomOv')?.remove();window._rawImgZoom=false;})()`,
  'word-count':       `(function(){document.getElementById('_rawWordCnt')?.remove();})()`,
  'anti-tracking':    `(function(){document.getElementById('_rawAntiTrk')?.remove();})()`,
  'print-clean':      `(function(){document.getElementById('_rawPrint')?.remove();})()`,
  'smooth-scroll':    `(function(){document.getElementById('_rawSmooth')?.remove();})()`,
  'smart-copy':       `(function(){window._rawSmartCopy=false;})()`,
  'hide-comments':    `(function(){document.getElementById('_rawHideCom')?.remove();})()`,
  'link-preview':     `(function(){document.getElementById('_rawLinkPrev')?.remove();window._rawLinkPrev=false;})()`,
  'custom-cursor':    `(function(){document.getElementById('_rawCursorRing')?.remove();document.getElementById('_rawCursorCSS')?.remove();window._rawCursor=false;})()`,
  'auto-scroll':      `(function(){var b=document.getElementById('_rawAutoScrollBtn');if(b)b.remove();window._rawAutoScrollBtn=false;})()`,
  'high-contrast':    `(function(){document.getElementById('_rawHiCon')?.remove();})()`,
  'pip-mode':         `(function(){if(document.pictureInPictureElement)document.exitPictureInPicture().catch(function(){});window._rawPip=false;})()`,
  'sticky-notes':     `(function(){document.getElementById('_rawStickyNotes')?.remove();window._rawStickyNotes=false;})()`,
  'low-data':         `(function(){document.getElementById('_rawLowData')?.remove();document.getElementById('_rawLowDataBadge')?.remove();})()`,
  'neon-glow':        `(function(){document.getElementById('_rawNeonGlow')?.remove();})()`,
  'page-zoom':        `(function(){document.getElementById('_rawZoomCtrl')?.remove();try{if(document.body)document.body.style.zoom='';}catch(e){}window._rawZoomCtrl=false;})()`,
  'yt-ad':            `(function(){try{var ns=window.__ytAdNs;if(ns&&window[ns]){var o=window[ns];if(o.obs)o.obs.disconnect();if(o.iv)clearInterval(o.iv);if(o.wObs)o.wObs.disconnect();delete window[ns];}delete window.__ytAdNs;}catch(e){}})()`,
  'serif-mode':       `(function(){document.getElementById('_rawSerif')?.remove();})()`,
  'scroll-top':       `(function(){document.getElementById('_rawScrollTopBtn')?.remove();window._rawScrollTop=false;})()`,
  'code-highlight':   `(function(){document.getElementById('_rawCode')?.remove();})()`,
  'url-cleaner':      `(function(){window._rawUrlClean=false;})()`,
  'distraction-block':`(function(){document.getElementById('_rawDistract')?.remove();})()`,
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function load(file, fb) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fb; }
}
function save(file, data) {
  try { fs.writeFileSync(file, JSON.stringify(data)); } catch(e) {}
}

// ── Default settings ──────────────────────────────────────────────────────────
const DEF_SETTINGS = {
  adblockEnabled: true, blockTelemetry: true, blockCrossSite: true,
  strictPrivacy:  true, spoofUserAgent:  true, doNotTrack:    true,
  hardwareAcceleration: true, uaRotate: false,
  searchEngine: 'https://duckduckgo.com/?q=',
  homepage: 'newtab', accentColor: 'white',
  theme: 'midnight',
  discordRpcDisabled: true, // off by default — user must enable
  wallpaperColor: '#080808', wallpaper: null, liveWallpaperAudio: false,
  showSidebar: false, sidebarSites: [],
  showFavicons: true,
  hideNtLogo: false,
  blockingLevel: 'strict',
  extensions: {},
  translateLang: 'en',
  geoEnabled: false,
  geoRegion: 'new-york',
  // Diagnostics / telemetry (all optional, user controllable)
  // crashReports: anonymous crash/error reports
  // usageStats:   aggregate feature usage events
  // perfData:     basic performance snapshots (startup time, memory)
  // All default to false — user opts in during setup wizard (step 5)
  crashReports: false,
  usageStats:   false,
  perfData:     false,
  toolbar: { 'tb-geo': false, 'tb-calc': false, 'tb-notes': false },
  restoreSession: false,
  plugins: { css: '', cssEnabled: false, js: '', jsEnabled: false },
  preferredLanguage: 'en-US',
  aiProvider: '',   // '' = disabled | 'openai' | 'deepseek' | 'claude' | 'gemini'
  aiApiKey:   '',   // stored locally, never sent to Lander servers
  aiModel:    '',   // '' = default per provider
  aiTemperature: 0.5,
  aiMaxTokens: 400,
  aiCustomPrompt: '',
  downloadPath: '',          // '' = use system default Downloads folder
  askDownloadPath: false,
  autoOpenDownloads: false,
  autoOpenFile: false,
};

// ── App state (populated in initStorage after app ready) ──────────────────────
let settings      = { ...DEF_SETTINGS };
let bookmarks     = [];
let history       = [];
let downloads     = [];
let userWhitelist = [];
const _downloadItems = new Map(); // id → DownloadItem (for pause/resume/cancel)
let F             = {};   // file paths, set in initStorage()

// ── Discord Rich Presence ─────────────────────────────────────────────────────
const DISCORD_CLIENT_ID = '1478113622717632562';
let discordRpc        = null;
let _rpcScreen        = 'newtab'; // current screen: 'newtab' | 'website' | 'settings' | 'addons'
const _rpcStartTime   = Date.now();

function _getRpcActivity() {
  switch (_rpcScreen) {
    case 'settings': return { details: 'In Settings',    state: 'Lander Browser' };
    case 'addons':   return { details: 'In Add-Ons',     state: 'Lander Browser' };
    case 'newtab':   return { details: 'On the New Tab', state: 'Lander Browser' };
    default:         return { details: 'Browsing the Web', state: 'Lander Browser' };
  }
}

function updateDiscordRPC() {
  if (!discordRpc) return;
  const { details, state } = _getRpcActivity();
  discordRpc.setActivity({
    details,
    state,
    startTimestamp: _rpcStartTime,
    largeImageKey:  'logo',
    largeImageText: 'Lander Browser',
    buttons: [{ label: 'Try Lander Browser!', url: 'https://rawbrowser.pages.dev' }],
  }).catch(err => console.error('[Discord RPC] setActivity error:', err?.message || err));
}

let _rpcInterval = null;

function initDiscordRPC() {
  if (settings.discordRpcDisabled || settings.gameMode) return; // user disabled RPC or game mode active
  try {
    const DiscordRPC = require('discord-rpc');
    discordRpc = new DiscordRPC.Client({ transport: 'ipc' });
    discordRpc.on('ready', () => {
      updateDiscordRPC();
      // Periodic sync every 15 s as a safety net — catches any missed reactive updates
      if (_rpcInterval) clearInterval(_rpcInterval);
      _rpcInterval = setInterval(() => {
        if (!discordRpc) return;
        // Re-derive state from actual tab if not in an overlay screen
        if (!['settings', 'addons'].includes(_rpcScreen)) {
          const activeTab = tabMap.get(activeId);
          const derived = (!activeTab || activeTab.url === 'newtab') ? 'newtab' : 'website';
          if (derived !== _rpcScreen) { _rpcScreen = derived; }
        }
        updateDiscordRPC();
      }, 15000);
    });
    discordRpc.login({ clientId: DISCORD_CLIENT_ID }).catch(() => {
      // Discord not running or user not logged in — silently skip
      discordRpc = null;
    });
  } catch {
    discordRpc = null;
  }
}

ipcMain.on('rpc:state', (_, screen) => {
  if (screen === 'tab') {
    // Resolve 'tab' to actual tab state based on the currently active tab
    const activeTab = tabMap.get(activeId);
    _rpcScreen = (!activeTab || activeTab.url === 'newtab') ? 'newtab' : 'website';
  } else if (['settings', 'addons', 'newtab', 'website'].includes(screen)) {
    _rpcScreen = screen;
  } else {
    return;
  }
  updateDiscordRPC();
});

// ── Telemetry / crash reporting ───────────────────────────────────────────────
const CRASH_ENDPOINT = new URL('https://rawbrowsercrashreports.rubikmaster49.workers.dev/');

function _buildDiscordPayload(kind, payload) {
  const now = new Date().toISOString();
  const baseFields = [
    {
      name: 'App',
      value: `Lander Browser v${app.getVersion()} • Electron ${process.versions.electron}`,
      inline: false,
    },
    {
      name: 'Platform',
      value: `${process.platform} ${os.release()} (${process.arch})`,
      inline: false,
    },
  ];

  if (kind === 'crash') {
    const err = payload.error || {};
    const msg = (err.message || String(err)).slice(0, 1024);
    const stack = (err.stack || payload.stack || '')
      .replace(/\u001b\[[0-9;]*m/g, '')
      .slice(0, 1024);
    const where = payload.where || 'unknown';
    return {
      embeds: [{
        title: 'Crash Report',
        description: `Location: **${where}**`,
        color: 0xff5555,
        fields: [
          ...baseFields,
          { name: 'Error', value: msg || '(no message)', inline: false },
          ...(stack ? [{ name: 'Stack', value: '```text\n' + stack + '\n```', inline: false }] : []),
        ],
        timestamp: now,
      }],
    };
  }

  if (kind === 'usage') {
    return {
      embeds: [{
        title: 'Usage Event',
        color: 0x14b8a6,
        fields: [
          ...baseFields,
          { name: 'Event', value: payload.event || 'unknown', inline: false },
        ],
        timestamp: now,
      }],
    };
  }

  if (kind === 'perf') {
    const memTotal = os.totalmem();
    const memFree  = os.freemem();
    const toMB = n => Math.round(n / 1048576);
    return {
      embeds: [{
        title: 'Performance Snapshot',
        color: 0x22c55e,
        fields: [
          ...baseFields,
          { name: 'Event', value: payload.event || 'baseline', inline: false },
          {
            name: 'Memory',
            value: `Total: ${toMB(memTotal)} MB\nFree: ${toMB(memFree)} MB`,
            inline: false,
          },
        ],
        timestamp: now,
      }],
    };
  }

  return {
    embeds: [{
      title: 'Telemetry',
      color: 0x06b6d4,
      fields: baseFields,
      timestamp: now,
    }],
  };
}

function sendTelemetry(kind, payload) {
  try {
    let enabled = false;
    if (kind === 'crash') enabled = settings.crashReports !== false;
    else if (kind === 'usage') enabled = !!settings.usageStats;
    else if (kind === 'perf')  enabled = !!settings.perfData;
    if (!enabled) return;

    const body = JSON.stringify(_buildDiscordPayload(kind, payload || {}));
    const req = https.request({
      method: 'POST',
      hostname: CRASH_ENDPOINT.hostname,
      path: CRASH_ENDPOINT.pathname,
      port: 443,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, res => {
      // Drain response to free socket; we don't care about body
      res.on('data', () => {});
    });
    req.on('error', () => {});
    req.write(body);
    req.end();
  } catch {
    // Never let telemetry throw
  }
}

// ── Filter list downloader / local cache ──────────────────────────────────────
// Downloads EasyList and EasyPrivacy ONCE, saves to disk, then reads locally.
// On subsequent runs the local copy is used — no CDN contact on every request.
// Cache is refreshed when the user clicks "Refresh filter lists" or files are > 4 days old.

const FILTER_SOURCES = [
  { name: 'easylist',    url: 'https://easylist.to/easylist/easylist.txt' },
  { name: 'easyprivacy', url: 'https://easylist.to/easylist/easyprivacy.txt' },
  { name: 'annoyances',  url: 'https://secure.fanboy.co.nz/fanboy-annoyance.txt' },
  { name: 'social',      url: 'https://easylist.to/easylist/fanboy-social.txt' },
  { name: 'malware',     url: 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt' },
];
const FILTER_MAX_AGE_MS = 4 * 24 * 60 * 60 * 1000; // 4 days

let _filterDomains = new Set();  // domains parsed from locally-cached filter lists
let _filterRulesCount = 0;
let _enabledFilterLists = { easylist: true, easyprivacy: true, annoyances: true, social: false, malware: false };

// Parse ABP/uBlock rules — extract only simple hostname-level block rules (||domain.com^)
function _parseABPDomains(text) {
  const out = new Set();
  for (const raw of text.split('\n')) {
    const l = raw.trim();
    if (!l || l[0] === '!' || l[0] === '[') continue;
    if (l.startsWith('@@'))     continue;  // whitelist rule — skip
    if (l.includes('##') || l.includes('#@#') || l.includes('#?#')) continue; // cosmetic
    if (!l.startsWith('||'))    continue;  // only host-block rules
    const hat = l.indexOf('^', 2);
    if (hat === -1) continue;
    const domain = l.slice(2, hat).toLowerCase().replace(/^www\./, '');
    // Validate: plain hostname, no wildcards, no path, no port
    if (/^[a-z0-9][a-z0-9._-]*\.[a-z]{2,}$/.test(domain)) out.add(domain);
  }
  return out;
}

function _fetchText(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? require('https') : require('http');
    const req = mod.get(url, { timeout: 45000, headers: { 'User-Agent': 'Lander Browser/1.0' } }, res => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return _fetchText(res.headers.location).then(resolve, reject);
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error('HTTP ' + res.statusCode)); }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end',  () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

async function _loadFilterLists(forceRefresh = false) {
  const filterDir = path.join(app.getPath('userData'), 'landerbrowser', 'filters');
  // Use async mkdir — avoids blocking the main thread
  await fs.promises.mkdir(filterDir, { recursive: true }).catch(() => {});

  const allDomains = new Set();
  for (const src of FILTER_SOURCES) {
    if (!_enabledFilterLists[src.name]) continue; // skip disabled lists
    const filePath = path.join(filterDir, src.name + '.txt');
    let text = null;

    // Use local cache if fresh enough (all async — never blocks event loop)
    if (!forceRefresh) {
      try {
        const st = await fs.promises.stat(filePath);
        if (Date.now() - st.mtimeMs < FILTER_MAX_AGE_MS) {
          text = await fs.promises.readFile(filePath, 'utf8');
        }
      } catch { /* file missing or unreadable — fall through to download */ }
    }

    // Download if no local copy or stale
    if (!text) {
      try {
        text = await _fetchText(src.url);
        await fs.promises.writeFile(filePath, text, 'utf8').catch(() => {});
      } catch {
        // Download failed — try any cached copy regardless of age
        try { text = await fs.promises.readFile(filePath, 'utf8'); } catch {}
      }
    }

    if (text) {
      const domains = _parseABPDomains(text);
      for (const d of domains) allDomains.add(d);
      // Yield to the event loop between files so IPC stays responsive
      await new Promise(r => setImmediate(r));
    }
  }

  _filterDomains = allDomains;
  _filterRulesCount = allDomains.size;
  return allDomains.size;
}

// Called inside app.whenReady() — app.getPath() only works after ready
function initStorage() {
  const DATA = path.join(app.getPath('userData'), 'landerbrowser');
  if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });
  F = {
    settings:  path.join(DATA, 'settings.json'),
    history:   path.join(DATA, 'history.json'),
    bookmarks: path.join(DATA, 'bookmarks.json'),
    downloads: path.join(DATA, 'downloads.json'),
    whitelist: path.join(DATA, 'whitelist.json'),
    sessions:  path.join(DATA, 'sessions.json'),
  };
  settings      = { ...DEF_SETTINGS, ...load(F.settings,  {}) };
  bookmarks     = load(F.bookmarks, []);
  history       = load(F.history,   []);
  downloads     = load(F.downloads, []);
  userWhitelist = load(F.whitelist, []);
}

// Global crash/exception hooks (main process only)
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception in main process:', err);
  sendTelemetry('crash', { where: 'main:uncaughtException', error: err });
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection in main process:', reason);
  const err = reason instanceof Error ? reason : new Error(String(reason));
  sendTelemetry('crash', { where: 'main:unhandledRejection', error: err });
});

app.on('render-process-gone', (event, webContents, details) => {
  sendTelemetry('crash', {
    where: 'renderer:' + (details?.reason || 'unknown'),
    error: new Error(details?.reason || 'renderer-process-gone'),
  });
});

app.on('child-process-gone', (event, details) => {
  sendTelemetry('crash', {
    where: 'child:' + (details?.type || 'unknown'),
    error: new Error(details?.reason || 'child-process-gone'),
  });
});

// ── Runtime ───────────────────────────────────────────────────────────────────
let   CHROME_H   = 82;   // matches --chrome-h; updated dynamically for compact mode (72)
const NAV_H      = 48;   // nav-row height — used as chrome-h in vtabs mode (--nav-h)
const NAV_H_COMPACT = 42; // compact mode nav height
const SIDEBAR_W  = 64;   // sidebar strip width
let   VTAB_W     = 220;  // vertical tab panel width (user-resizable)
let   sidebarOn      = false;
let   verticalTabsOn = false;
let   nextId     = 0;
const tabMap   = new Map();
const wcIdMap  = new Map(); // webContentsId → tabId — O(1) lookup in request handlers
let   activeId = null;
let   _snapInterval = null; // cleared on quit to prevent dangling callbacks
let   win      = null;
let   totalBlocked = 0;
let   panelOpen    = false;
let   panelClipX   = 0;       // >0 = BV clipped to leave room for open panel
let   _omniParked  = false;   // true while BV is parked for the omni dropdown
let   _panelSeq         = 0;        // increments on every panel:show:* to cancel stale async chains

// ── IPC shortcut ──────────────────────────────────────────────────────────────
let _dlPopupThrottleTimer = null;
let _dlPopupPendingArgs   = null;

function send(ch, ...a) {
  if (win && !win.isDestroyed()) win.webContents.send(ch, ...a);
  // Throttle download updates to popup window — max 2 per second to prevent
  // IPC flooding that causes video playback quality drops on the main window.
  if (ch === 'downloads:update') {
    const dlp = _panelPopups.dl;
    if (dlp?.win && !dlp.win.isDestroyed()) {
      _dlPopupPendingArgs = a;
      if (!_dlPopupThrottleTimer) {
        dlp.win.webContents.send('dl:list', ...a);
        _dlPopupPendingArgs = null;
        _dlPopupThrottleTimer = setTimeout(() => {
          _dlPopupThrottleTimer = null;
          const dlp2 = _panelPopups.dl;
          if (_dlPopupPendingArgs && dlp2?.win && !dlp2.win.isDestroyed()) {
            dlp2.win.webContents.send('dl:list', ..._dlPopupPendingArgs);
            _dlPopupPendingArgs = null;
          }
        }, 500);
      }
    }
  }
  // Forward audio updates to media popup window
  if (ch === 'audio:update') {
    const mp = _panelPopups.media;
    if (mp?.win && !mp.win.isDestroyed()) mp.win.webContents.send('audio:update', ...a);
  }
  // Forward bookmark updates to bookmarks popup window
  if (ch === 'bookmarks:set') {
    const bp = _panelPopups.bm;
    if (bp?.win && !bp.win.isDestroyed()) bp.win.webContents.send('bookmarks:set', ...a);
  }
  // Forward settings updates to geo popup window
  if (ch === 'settings:set') {
    const gp = _panelPopups.geo;
    if (gp?.win && !gp.win.isDestroyed()) gp.win.webContents.send('settings:set', ...a);
  }
  // Forward ytdlp updates to ytdlp popup window
  if (ch === 'ytdlp:status' || ch === 'ytdlp:progress' || ch === 'ytdlp:done' || ch === 'ytdlp:error') {
    const yp = _panelPopups.ytdlp;
    if (yp?.win && !yp.win.isDestroyed()) yp.win.webContents.send(ch, ...a);
  }
}

// ── Tab groups ────────────────────────────────────────────────────────────────
const groupMap      = new Map(); // groupId → { id, name, color, collapsed }
let   _nextGroupId  = 1;

const GROUP_COLORS = ['blue','purple','red','orange','yellow','green','teal','pink','grey','cyan'];

function sendGroupsUpdate() {
  send('groups:update', [...groupMap.values()]);
}

/** Extract a short readable name from a URL for auto-naming groups */
function _domainLabel(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, '');
    // Use second-level domain capitalized (e.g. "youtube.com" → "YouTube")
    const parts = host.split('.');
    const name = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
    return name.charAt(0).toUpperCase() + name.slice(1);
  } catch { return null; }
}

/** Extract hostname from URL for grouping comparison */
function _tabHost(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return null; }
}

// ── Tab serialization ─────────────────────────────────────────────────────────
function tabData(t) {
  return {
    id: t.id, url: t.url, title: t.title,
    favicon: t.favicon, loading: t.loading,
    pinned: t.pinned, muted: t.muted,
    isAudible: t.isAudible || false,
    groupId: t.groupId || null,
  };
}

function _getAudioTabs() {
  return [...tabMap.values()]
    .filter(t => t.isAudible || t.muted)
    .map(t => ({ id: t.id, title: t.title, favicon: t.favicon, isAudible: t.isAudible, muted: t.muted, volume: t.volume ?? 1, paused: t.paused ?? false }));
}

function navData(t) {
  const wc = t?.bv?.webContents;
  return {
    url:          t?.url     || '',
    canBack:      wc ? (wc.navigationHistory?.canGoBack()    ?? wc.canGoBack())    : false,
    canFwd:       wc ? (wc.navigationHistory?.canGoForward() ?? wc.canGoForward()) : false,
    loading:      t?.loading || false,
    favicon:      t?.favicon || null,
    muted:        t?.muted   || false,
    zoom:         t?.zoom    || 1,
    blocked:      t?.blocked || 0,
    blockedTotal: totalBlocked,
  };
}

// ── BrowserView sizing ────────────────────────────────────────────────────────
// Leave a 5px strip on all free edges so OS resize handles are never blocked
// by the BrowserView. On Windows/Linux the resize hot-zone is ~4px.
const RESIZE_GAP = process.platform === 'win32' || process.platform === 'linux' ? 5 : 0;

function setBounds(bv) {
  if (!win || !bv) return;
  const [w, h] = win.getContentSize();
  let x, y, bvH;
  if (verticalTabsOn) {
    // Vertical tabs v2: toolbar stays at top (NAV_H tall), tabs are a left sidebar.
    const navH = settings.compactMode ? NAV_H_COMPACT : NAV_H;
    x   = VTAB_W;
    y   = navH;
    bvH = Math.max(h - navH - RESIZE_GAP, 0);
  } else {
    x  = sidebarOn ? SIDEBAR_W : 0;
    y  = CHROME_H;
    bvH = Math.max(h - CHROME_H - RESIZE_GAP, 0);
  }
  // If a panel is clipping the BV width (to show panel in uncovered area), respect it
  const fullW = Math.max(0, w - x - RESIZE_GAP);
  const bvW = panelClipX > 0 ? Math.max(0, panelClipX - x) : fullW;
  bv.setBounds({ x, y, width: bvW, height: bvH });
}

// ── URL helpers ───────────────────────────────────────────────────────────────
function normalizeUrl(raw) {
  if (!raw || raw === 'about:blank') return 'newtab';
  if (raw.includes('newtab.html'))   return 'newtab';
  return raw;
}

function resolveUrl(raw) {
  if (!raw || raw === 'newtab') return 'newtab';
  
  // Get the current search engine from settings
  const engine = settings?.searchEngine || 'https://duckduckgo.com/?q=';
  
  // Allow file:// URLs and bare paths pointing to local files
  if (/\.(html?|xhtml|pdf)$/i.test(raw) && !/^(javascript|vbscript|data):/i.test(raw)) return raw;
  
  // Security: never navigate to dangerous schemes — treat as search queries
  if (/^(javascript|vbscript|data|file):/i.test(raw)) return engine + encodeURIComponent(raw);
  if (/^(https?|ftp):\/\//i.test(raw))   return raw;
  if (/^(about:|view-source:)/i.test(raw)) return raw;
  if (/^localhost(:\d+)?(\/.*)?$/.test(raw)) return 'http://' + raw;
  if (/^[\w-]+(\.[\w-]+)+(\/.*)?$/.test(raw)) return 'https://' + raw;
  return engine + encodeURIComponent(raw);
}

function stripTracking(url) {
  if (!settings.strictPrivacy) return url;
  try {
    const u = new URL(url);
    ['utm_source','utm_medium','utm_campaign','utm_term','utm_content',
     'fbclid','gclid','msclkid','twclid','dclid','mc_eid','mc_cid','ref'
    ].forEach(p => u.searchParams.delete(p));
    return u.toString();
  } catch { return url; }
}

function addHistory(url, title) {
  if (!url || url === 'newtab' || url.startsWith('about:') || url.startsWith('file://')) return;
  history.unshift({ url, title: title || url, ts: Date.now() });
  if (history.length > 10000) history.length = 10000;
  save(F.history, history);
  send('history:set', history);
}

// ── Tab activation ─────────────────────────────────────────────────────────────
function activateTab(id) {
  const tab = tabMap.get(id);
  if (!tab || !win) return;

  // Auto-expand collapsed group when switching to a tab inside it
  if (tab.groupId) {
    const g = groupMap.get(tab.groupId);
    if (g && g.collapsed) { g.collapsed = false; sendGroupsUpdate(); }
  }

  // If a panel was open, close it now — switching tabs must always restore the UI
  if (panelOpen) {
    panelOpen  = false;
    panelClipX = 0;
    // Restore the outgoing tab's BV dimensions in case it was parked at 2×2
    const oldTab = tabMap.get(activeId);
    if (oldTab?.bv && !oldTab.bv.webContents.isDestroyed()) {
      oldTab.bv.webContents.executeJavaScript(PANEL_RESTORE_ALIVE_JS).catch(() => {});
    }
    // Tell the renderer to close any open panel / overlay
    send('panels:closeAll');
  }

  // Remove all BrowserViews first
  for (const t of tabMap.values()) {
    if (t.bv) try { win.removeBrowserView(t.bv); } catch {}
  }
  
  // Only attach BrowserView for real pages — newtab is handled by HTML newtab-layer
  // Set correct bounds BEFORE addBrowserView so the view appears at the right position
  // on the very first frame, preventing the 1-frame shift from (0,0) to the real origin.
  if (tab.bv && tab.url !== 'newtab') {
    setBounds(tab.bv);
    win.addBrowserView(tab.bv);
  }
  
  activeId = id;
  tab.lastActiveTime = Date.now();

  // Resume suspended tab: reload the saved URL
  if (tab.suspended && tab.suspendedUrl) {
    tab.suspended = false;
    const restore = tab.suspendedUrl;
    tab.suspendedUrl = null;
    tab.url = restore;
    try {
      tab.bv.webContents.setBackgroundThrottling(false);
      tab.bv.webContents.loadURL(restore).catch(() => {});
    } catch {}
  }

  send('tab:activate', id);
  send('nav:state', navData(tab));
  // Always refresh privacy-panel stats when switching tabs
  send('blocked:update', { total: totalBlocked, session: tab.blocked || 0 });
  // Update Discord RPC for the new active tab
  _rpcScreen = (tab.url === 'newtab') ? 'newtab' : 'website';
  updateDiscordRPC();

  // Re-apply enabled extensions on the newly activated tab.
  // Extensions are self-guarded (check window._rawX before running) so this
  // is safe to call even if the extension was already injected on this page.
  if (tab.bv && tab.url !== 'newtab' && !tab.bv.webContents.isDestroyed()) {
    const exts = settings.extensions || {};
    for (const [extId, enabled] of Object.entries(exts)) {
      if (enabled && EXT_SCRIPTS[extId]) {
        tab.bv.webContents.executeJavaScript(EXT_SCRIPTS[extId]).catch(() => {});
      }
    }
    // Re-apply custom plugins on tab switch
    const _pl = settings.plugins || {};
    if (_pl.cssEnabled && _pl.css) tab.bv.webContents.insertCSS(_pl.css, { cssOrigin: 'user' }).catch(() => {});
    if (_pl.jsEnabled  && _pl.js)  tab.bv.webContents.executeJavaScript(_pl.js).catch(() => {});
    // Refresh snapshot so any panel opened on this tab shows a current screenshot
    tab.bv.webContents.capturePage().then(img => {
      tab.snapshot = 'data:image/jpeg;base64,' + img.toJPEG(60).toString('base64');
    }).catch(() => {});
  }
}

// ── Tab creation ───────────────────────────────────────────────────────────────
function createTab(url, activate = true) {
  const id = ++nextId;
  const bv = new BrowserView({
    backgroundColor: '#080808',
    webPreferences: {
      nodeIntegration:  false,
      contextIsolation: true,
      sandbox:          true,
      partition:        'persist:main',
      preload:          path.join(__dirname, 'preload.js'),
      webSecurity: true,
      allowRunningInsecureContent: false,
      experimentalFeatures: true,
    },
  });

  const tab = {
    id, bv,
    url: 'newtab', title: 'New Tab', favicon: null,
    loading: false, pinned: false, muted: false, zoom: 1, blocked: 0,
    lastActiveTime: Date.now(), suspended: false, suspendedUrl: null, memMB: 0,
  };
  tabMap.set(id, tab);
  wcIdMap.set(bv.webContents.id, id); // register for O(1) lookup in request handlers

  const wc = bv.webContents;
  // Electron adds its own internal listeners per-WebContents (e.g. for devtools,
  // remote module, etc.). Raise the limit so our app listeners don't trigger the
  // spurious "Possible EventEmitter memory leak detected" warning.
  wc.setMaxListeners(30);
  // Prevent Chromium from throttling/pausing the renderer when it's not
  // composited into the window (e.g. while a toolbar panel is open with BV removed).
  // Without this, video/audio can pause at the media pipeline level regardless of
  // any JS-level visibility overrides.
  wc.setBackgroundThrottling(false);
  // Per-tab UA rotation: when enabled, each new tab gets a randomly-selected UA.
  const tabUA = settings.uaRotate
    ? _UA_ROTATE_POOL[Math.floor(Math.random() * _UA_ROTATE_POOL.length)]
    : (settings.spoofUserAgent !== false ? SPOOF_UA : undefined);
  if (tabUA) wc.setUserAgent(tabUA);

  // Auth provider domains that use popup-based OAuth flows.
  // Returning { action: 'allow' } lets Electron create a real popup window so the
  // parent page can hold onto the window reference and detect when login completes.
  const _oauthDomains = [
    'accounts.google.com', 'google.com', 'googleusercontent.com',
    'login.microsoftonline.com', 'appleid.apple.com',
    'facebook.com', 'discord.com',
    'accounts.spotify.com', 'spotify.com',
  ];
  wc.setWindowOpenHandler(({ url: u }) => {
    // Block dangerous schemes
    if (/^(javascript|vbscript|file):/i.test(u)) return { action: 'deny' };
    // Allow native popup for OAuth providers so the auth flow can complete.
    // Also allow about:blank popups — many OAuth flows open about:blank first,
    // then navigate to the auth URL from JS.
    const isBlank = !u || u === 'about:blank';
    let isAuth = false;
    if (!isBlank) {
      try {
        const host = new URL(u).hostname;
        isAuth = _oauthDomains.some(d => host === d || host.endsWith('.' + d));
      } catch {}
    }
    if (isAuth || isBlank) {
      return {
        action: 'allow',
        overrideBrowserWindowOptions: {
          width: 500, height: 650,
          autoHideMenuBar: true,
          webPreferences: {
            partition: 'persist:main',
            contextIsolation: true,
            nodeIntegration: false,
            preload: path.join(__dirname, 'preload.js'),
          },
        },
      };
    }
    createTab(u, true);
    return { action: 'deny' };
  });

  // Apply UA spoofing to OAuth popup windows.
  // IMPORTANT: Do NOT add a will-navigate guard here — OAuth flows redirect the
  // popup to the original site's callback URL (e.g. example.com/oauth/callback)
  // to pass the auth code. Intercepting that navigation closes the popup before
  // the parent page can read the result, permanently breaking login.
  wc.on('did-create-window', (popup) => {
    const pwc = popup.webContents;
    pwc.setUserAgent(SPOOF_UA);
    pwc.setBackgroundThrottling(false);
    popup.setMenuBarVisibility(false);
    popup.on('closed', () => { try { pwc.removeAllListeners(); } catch {} });
    // Inject Google UA fix at the earliest moment (before page scripts) + on later events.
    pwc.on('did-commit-navigation', (_, navUrl) => {
      if (navUrl && _GOOGLE_RE.test(navUrl)) pwc.executeJavaScript(GOOGLE_UA_FIX).catch(() => {});
    });
    pwc.on('dom-ready', () => _injectGoogleUAFix(pwc));
    pwc.on('did-navigate', () => _injectGoogleUAFix(pwc));
    pwc.on('did-navigate-in-page', () => _injectGoogleUAFix(pwc));
  });

  // Inject Google UA fix at the EARLIEST possible moment (did-commit-navigation fires
  // before page scripts run — earlier than dom-ready) so Google never sees Electron.
  wc.on('did-commit-navigation', (_, navUrl) => {
    if (navUrl && _GOOGLE_RE.test(navUrl)) wc.executeJavaScript(GOOGLE_UA_FIX).catch(() => {});
  });
  // Belt-and-suspenders: also inject on later events to cover SPA navigations.
  wc.on('dom-ready', () => {
    _injectGoogleUAFix(wc);
    // Inject scrollbar-hiding CSS at dom-ready — skip TikTok because their
    // scroll-to-next-video button depends on the page's scrollbar state.
    // Also skip search engine pages to prevent layout shifts on Images/etc. tabs.
    const _domReadyUrl = wc.getURL() || '';
    if (!/tiktok\.com/i.test(_domReadyUrl) && !/google\.com|bing\.com|search\.brave\.com|duckduckgo\.com|yahoo\.com|startpage\.com|kagi\.com|searx\./i.test(_domReadyUrl)) {
      wc.insertCSS(
        'html { overflow-y: overlay !important; scrollbar-width: thin !important; }' +
        'html::-webkit-scrollbar { width: 6px !important; height: 6px !important; background: transparent !important; }' +
        'html::-webkit-scrollbar-thumb { background: rgba(128,128,128,.3) !important; border-radius: 3px !important; }' +
        'html::-webkit-scrollbar-thumb:hover { background: rgba(128,128,128,.5) !important; }' +
        'html::-webkit-scrollbar-track { background: transparent !important; }',
        { cssOrigin: 'user' }
      ).catch(() => {});
    }
    // Geo injection at dom-ready for early interception (before page JS runs)
    if (settings.geoEnabled && settings.geoRegion && GEO_REGIONS[settings.geoRegion]) {
      const gr = GEO_REGIONS[settings.geoRegion];
      wc.executeJavaScript(buildGeoScript(gr.lat, gr.lon)).catch(() => {});
    }
    // Inject yt-ad at dom-ready so fetch/XHR intercepts are in place BEFORE
    // YouTube's player scripts execute and make ad-related network requests.
    if (/youtube\.com/i.test(_domReadyUrl) && settings.extensions?.['yt-ad'] && !/\/shorts\//i.test(_domReadyUrl)) {
      wc.executeJavaScript(YT_AD_SKIP).catch(() => {});
    }
  });
  wc.on('did-navigate', () => _injectGoogleUAFix(wc));
  wc.on('did-navigate-in-page', () => _injectGoogleUAFix(wc));

  // ── Right-click context menu ───────────────────────────────────────────────
  wc.on('context-menu', (_, p) => {
    const groups = [];

    if (p.linkURL && !/^(javascript|vbscript):/i.test(p.linkURL)) {
      groups.push([
        { label: 'Open Link in New Tab',            click: () => createTab(p.linkURL, true)  },
        { label: 'Open Link in Background Tab',     click: () => createTab(p.linkURL, false) },
        { label: 'Copy Link Address',               click: () => clipboard.writeText(p.linkURL) },
      ]);
    }

    if (p.hasImageContents && p.srcURL) {
      groups.push([
        { label: 'Open Image in New Tab', click: () => createTab(p.srcURL, false) },
        { label: 'Copy Image',            click: () => wc.copyImageAt(p.x, p.y)  },
        { label: 'Copy Image Address',    click: () => clipboard.writeText(p.srcURL) },
        { label: 'Save Image As…',        click: () => wc.downloadURL(p.srcURL) },
      ]);
    }

    if (p.selectionText) {
      const q = p.selectionText.slice(0, 50);
      groups.push([
        { label: 'Copy',                   click: () => clipboard.writeText(p.selectionText) },
        { label: `Search "${q}${p.selectionText.length > 50 ? '…' : ''}"`,
          click: () => createTab((settings.searchEngine || 'https://duckduckgo.com/?q=') + encodeURIComponent(p.selectionText), true) },
      ]);
    }

    if (p.isEditable) {
      groups.push([
        { label: 'Emoji Picker', click: () => app.showEmojiPanel() },
        { type: 'separator' },
        { label: 'Cut',       role: 'cut',       enabled: p.editFlags.canCut       },
        { label: 'Copy',      role: 'copy',      enabled: p.editFlags.canCopy      },
        { label: 'Paste',     role: 'paste',     enabled: p.editFlags.canPaste     },
        { type: 'separator' },
        { label: 'Undo',      role: 'undo',      enabled: p.editFlags.canUndo      },
        { label: 'Redo',      role: 'redo',      enabled: p.editFlags.canRedo      },
        { type: 'separator' },
        { label: 'Select All',role: 'selectAll', enabled: p.editFlags.canSelectAll },
      ]);
    }

    groups.push([
      { label: 'Back',    enabled: wc.navigationHistory?.canGoBack()    ?? wc.canGoBack(),    click: () => wc.goBack()    },
      { label: 'Forward', enabled: wc.navigationHistory?.canGoForward() ?? wc.canGoForward(), click: () => wc.goForward() },
      { label: 'Reload',  click: () => wc.reload() },
    ]);

    if (settings.aiProvider && settings.aiApiKey) {
      const aiGroup = [];
      if (p.selectionText) {
        aiGroup.push({ label: 'Summarize Selection with AI', click: () => {
          win.webContents.send('ai:open-panel');
          ipcMain.emit('ai:summarize', null, { text: p.selectionText });
        }});
      }
      aiGroup.push({ label: 'Summarize Page with AI', click: async () => {
        win.webContents.send('ai:open-panel');
        try {
          const pageText = await wc.executeJavaScript(
            '(document.body ? document.body.innerText : document.documentElement.innerText || "").slice(0,8000)'
          );
          ipcMain.emit('ai:summarize', null, { text: pageText });
        } catch { send('ai:result', { error: 'Could not read page content.' }); }
      }});
      groups.push(aiGroup);
    }

    groups.push([
      { label: 'Translate Page', click: () => {
          const lang = settings.translateLang || 'en';
          const url  = wc.getURL();
          if (url && !url.startsWith('about:') && !url.includes('translate.google.com')) {
            tab.bv?.webContents.loadURL(_toTranslateUrl(url, lang));
          }
        }
      },
      { label: 'Print…',          click: () => wc.print() },
      { label: 'Save Page As…',   click: () => wc.downloadURL(wc.getURL()) },
      { label: 'View Page Source',click: () => createTab('view-source:' + wc.getURL(), true) },
      { label: 'Inspect Element', click: () => wc.inspectElement(p.x, p.y) },
    ]);

    const items = [];
    groups.forEach((g, i) => {
      items.push(...g);
      if (i < groups.length - 1) items.push({ type: 'separator' });
    });

    Menu.buildFromTemplate(items).popup({ window: win });
  });

  // ── Browser keyboard shortcuts when webpage has focus ─────────────────
  // Intercepts shortcuts before the page sees them so Ctrl+T, Ctrl+W, etc.
  // work even when a website (BrowserView) has keyboard focus.
  wc.on('before-input-event', (event, input) => {
    if (input.type !== 'keyDown') return;
    const M  = input.control || input.meta;
    const Sh = input.shift;
    const k  = input.key;

    // New tab
    if (M && !Sh && k === 't') { event.preventDefault(); createTab('newtab', true); return; }
    // Close tab
    if (M && !Sh && k === 'w') { event.preventDefault(); closeTab(id); return; }
    // Reload / hard reload
    if (M && !Sh && k === 'r') { event.preventDefault(); wc.reload(); return; }
    if (M && Sh  && k === 'R') { event.preventDefault(); wc.reloadIgnoringCache(); return; }
    // Zoom
    if (M && (k === '=' || k === '+')) { event.preventDefault(); setZoom(id, z => Math.min(+(z + 0.1).toFixed(2), 3)); return; }
    if (M && k === '-')                { event.preventDefault(); setZoom(id, z => Math.max(+(z - 0.1).toFixed(2), 0.3)); return; }
    if (M && k === '0')                { event.preventDefault(); setZoom(id, () => 1); return; }
    // Back / Forward
    if ((M && k === '[') || (input.alt && k === 'ArrowLeft'))  { event.preventDefault(); wc.goBack();    return; }
    if ((M && k === ']') || (input.alt && k === 'ArrowRight')) { event.preventDefault(); wc.goForward(); return; }
    // DevTools
    if (k === 'F12' || (M && Sh && (k === 'I' || k === 'i'))) { event.preventDefault(); wc.openDevTools(); return; }
    // Renderer-side shortcuts — delegate to index.html
    if (M && !Sh && k === 'l') { event.preventDefault(); send('kb:omnibox');    return; }
    if (M && !Sh && k === 'f') { event.preventDefault(); send('kb:find');       return; }
    if (M && !Sh && k === 'd') { event.preventDefault(); send('kb:bookmark');   return; }
    if (M && !Sh && k === 'h') { event.preventDefault(); send('kb:history');    return; }
    if (M && !Sh && k === 'p') { event.preventDefault(); send('kb:print');      return; }
    if (M && Sh  && (k === 'B' || k === 'b')) { event.preventDefault(); send('kb:bm-panel'); return; }
    if (M && Sh  && (k === 'S' || k === 's')) { event.preventDefault(); send('kb:snip');     return; }
    // Switch tab by number
    if (M && k >= '1' && k <= '9') { event.preventDefault(); send('kb:switch-tab', parseInt(k)); return; }
  });

  // ── Block dangerous schemes + auto-upgrade HTTP → HTTPS ───────────────────
  const _LOCAL_RE = /^(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|::1|0\.0\.0\.0)/;
  const _guardNav = (e, url) => {
    if (/^(javascript|vbscript):/i.test(url)) { e.preventDefault(); return; }
    if (/^file:/i.test(url))                   { e.preventDefault(); return; }
    if (/^magnet:/i.test(url)) { e.preventDefault(); shell.openExternal(url).catch(() => {}); return; }
    // "Continue anyway" bypass from blocked-site page — raw-bypass://?h=HOST&u=ENCODED_URL
    if (/^raw-bypass:/i.test(url)) {
      e.preventDefault();
      try {
        const qi = url.indexOf('?');
        if (qi >= 0) {
          const p      = new URLSearchParams(url.slice(qi + 1));
          const host   = p.get('h') || '';
          const target = p.get('u') || '';
          if (host) _tempBypassSet.add(host.toLowerCase());
          if (target) wc.loadURL(target);
        }
      } catch {}
      return;
    }
    // Detect browser download/marketing sites — show informational promo popup
    // but allow navigation to proceed normally so user can visit the site.
    try {
      const _cu = new URL(url);
      const _host = _cu.hostname.replace(/^www\./, '');
      const _path = _cu.pathname;
      let _detectedBrowser = null;
      if (_host === 'chrome.com' ||
          (_host === 'google.com' && /^\/chrome(\/|$)/i.test(_path)) ||
          _host === 'chromewebstore.google.com') {
        _detectedBrowser = 'chrome';
      } else if (_host === 'firefox.com' || _host === 'getfirefox.com' ||
                 (_host === 'mozilla.org' && /^\/(en-[a-z]+\/)?firefox(\/|$)/i.test(_path))) {
        _detectedBrowser = 'firefox';
      } else if (_host === 'opera.com') {
        _detectedBrowser = 'opera';
      } else if (_host === 'microsoft.com' && /^\/edge(\/|$)/i.test(_path)) {
        _detectedBrowser = 'edge';
      } else if (_host === 'brave.com') {
        _detectedBrowser = 'brave';
      } else if (_host === 'apple.com' && /^\/safari(\/|$)/i.test(_path)) {
        _detectedBrowser = 'safari';
      } else if (_host === 'vivaldi.com') {
        _detectedBrowser = 'vivaldi';
      }
      if (_detectedBrowser) {
        // Show informational promo popup (non-blocking) — page still loads
        _showBrowserSwitchPopup(_detectedBrowser, _host);
      }
    } catch {}
    // Auto-upgrade plain HTTP to HTTPS for all non-local destinations.
    // Prevents credentials/personal data from being sent unencrypted.
    if (/^http:\/\//i.test(url)) {
      try {
        const host = new URL(url).hostname;
        if (!_LOCAL_RE.test(host) && !host.endsWith('.local')) {
          e.preventDefault();
          wc.loadURL(url.replace(/^http:/i, 'https:'));
        }
      } catch {}
    }
  };
  wc.on('will-navigate', _guardNav);
  wc.on('will-redirect', _guardNav);

  wc.on('did-start-loading', () => {
    tab.loading = true;
    // Keep the old snapshot alive — don't null it here. If a panel or context
    // menu opens while the next page is loading, the old screenshot is shown
    // rather than a blank black area.
    // tab.snapshot is cleared in did-stop-loading once the new page is ready.
    // Do NOT clear favicon here — SPA navigations (TikTok, YouTube) fire did-start-loading
    // but page-favicon-updated won't re-fire if the favicon link tag hasn't changed.
    // Favicon is cleared in did-navigate (cross-origin only) instead.
    send('tab:update', tabData(tab));
    if (id === activeId) send('nav:state', navData(tab));
  });

  wc.on('did-stop-loading', () => {
    tab.loading = false;
    tab.url     = normalizeUrl(wc.getURL()) || tab.url;
    send('tab:update', tabData(tab));
    if (id === activeId) {
      send('nav:state', navData(tab));
      // Keep RPC in sync with what the active tab is showing
      if (!['settings', 'addons'].includes(_rpcScreen)) {
        _rpcScreen = (tab.url === 'newtab') ? 'newtab' : 'website';
        updateDiscordRPC();
      }
    }
    addHistory(tab.url, tab.title);
    // Inject floating PiP button for any page that might have video
    // Always clear any stale guard first so re-navigation gets a fresh inject.
    if (tab.url && tab.url !== 'newtab' && !tab.url.startsWith('view-source:')) {
      wc.executeJavaScript('window._rawPipInjected=false;window._rawPipV3=false;').catch(()=>{});
      wc.executeJavaScript(VIDEO_PIP_INJECT).catch(() => {});
    }
    // Suppress double-scrollbar: some sites set overflow on both <html> and <body>,
    // causing Chromium to render two native scrollbars. Hiding the html-level one
    // via user-origin CSS fixes those sites without breaking normal page scrolling.
    // Skip TikTok — their scroll-to-next-video button logic depends on scrollbar state.
    // Also skip search engines to prevent layout shifts on Images/News/etc. result tabs.
    const _skipScrollbar = /tiktok\.com|google\.com|bing\.com|search\.brave\.com|duckduckgo\.com|yahoo\.com|startpage\.com|kagi\.com|searx\./i;
    if (!_skipScrollbar.test(tab.url || '')) {
      wc.insertCSS(
        'html { overflow-y: overlay !important; scrollbar-width: thin !important; }' +
        'html::-webkit-scrollbar { width: 6px !important; height: 6px !important; background: transparent !important; }' +
        'html::-webkit-scrollbar-thumb { background: rgba(128,128,128,.3) !important; border-radius: 3px !important; }' +
        'html::-webkit-scrollbar-thumb:hover { background: rgba(128,128,128,.5) !important; }' +
        'html::-webkit-scrollbar-track { background: transparent !important; }',
        { cssOrigin: 'user' }
      ).catch(() => {});
    }
    // Inject persistent media guard so IntersectionObserver/pause protection is
    // in place BEFORE any panel opens (fixes async race with _parkBV).
    if (tab.url && tab.url !== 'newtab' && !tab.url.startsWith('view-source:')) {
      wc.executeJavaScript(PERSISTENT_MEDIA_GUARD_JS).catch(() => {});
    }

    // Re-apply enabled extensions on every page load
    const exts = settings.extensions || {};
    for (const [extId, enabled] of Object.entries(exts)) {
      if (enabled && EXT_SCRIPTS[extId]) {
        wc.executeJavaScript(EXT_SCRIPTS[extId]).catch(() => {});
      }
    }
    // Inject custom CSS/JS plugins
    const _pl = settings.plugins || {};
    tab._pluginCSSKey = null; // reset on navigation
    if (_pl.cssEnabled && _pl.css) wc.insertCSS(_pl.css, { cssOrigin: 'user' }).then(key => { tab._pluginCSSKey = key; }).catch(() => {});
    if (_pl.jsEnabled  && _pl.js)  wc.executeJavaScript(_pl.js).catch(() => {});
    // Inject geolocation spoofer when enabled
    if (settings.geoEnabled && settings.geoRegion && GEO_REGIONS[settings.geoRegion]) {
      const gr = GEO_REGIONS[settings.geoRegion];
      wc.executeJavaScript(buildGeoScript(gr.lat, gr.lon)).catch(() => {});
    }
    // Background snapshot — taken immediately + refreshed at 1.5s for SPAs.
    // Keeping a fresh screenshot means panels/context-menus can show the
    // website instantly without a blank flash.
    if (id === activeId && tab.url !== 'newtab' && !tab.url.startsWith('view-source:')) {
      const _doSnap = () => {
        if (!panelOpen && tab?.bv && !tab.bv.webContents.isDestroyed()) {
          tab.bv.webContents.capturePage().then(img => {
            tab.snapshot = 'data:image/jpeg;base64,' + img.toJPEG(60).toString('base64');
          }).catch(() => {});
        }
      };
      _doSnap(); // immediate capture right after load
      setTimeout(() => { if (activeId === id) _doSnap(); }, 1500); // re-capture for SPA updates
    }
    // Auto-translate: if enabled, translate the page into the target language.
    // We detect the page language via <html lang>; if that attribute is absent
    // we fall back to the content-language header or the navigator.language of
    // the page itself.  Pages already in the target language are skipped.
    if (settings.autoTranslate && tab.url !== 'newtab' && !tab.url.includes('translate.google.com') && !tab.url.includes('.translate.goog')) {
      const targetLang = (settings.translateLang || 'en').split('-')[0].toLowerCase();
      const detectScript = `(function(){
        var l=(document.documentElement.lang||'').trim().split('-')[0].toLowerCase();
        if(l&&l.length>=2)return l;
        var m=document.querySelector('meta[http-equiv="content-language"]');
        if(m){var ml=(m.content||'').trim().split('-')[0].toLowerCase();if(ml.length>=2)return ml;}
        var n=(navigator.language||'').split('-')[0].toLowerCase();
        return n||'';
      })()`;
      wc.executeJavaScript(detectScript).then(pageLang => {
        // If page lang is unknown (empty) we translate anyway — better to
        // translate an already-correct page than to miss a foreign one.
        const shouldTranslate = !pageLang || pageLang !== targetLang;
        if (shouldTranslate) {
          wc.loadURL(_toTranslateUrl(tab.url, targetLang));
        }
      }).catch(() => {});
    }
  });

  wc.on('media-started-playing', () => {
    tab.isAudible = true;
    send('tab:update', tabData(tab));
    send('audio:update', _getAudioTabs());
  });
  wc.on('media-paused', () => {
    tab.isAudible = wc.isCurrentlyAudible();
    send('tab:update', tabData(tab));
    send('audio:update', _getAudioTabs());
  });

  wc.on('did-fail-load', (_, errCode, errDesc, url) => {
    // Ignore cancelled loads (user navigated away, -3) and aborted subresources (-27)
    if (errCode === -3 || errCode === -27 || !url) return;
    tab.loading = false;
    send('tab:update', tabData(tab));
    if (id === activeId) send('nav:state', navData(tab));

    // Network-offline error codes → show offline game page
    const OFFLINE_CODES = new Set([-21, -100, -102, -106, -109, -118]);
    if (OFFLINE_CODES.has(errCode)) {
      wc.loadFile(path.join(__dirname, 'offline.html'), {
        query: { url: encodeURIComponent(url) },
      }).catch(() => {});
      return;
    }

    // DNS failure / site doesn't exist → friendly "can't find that site" page
    if (errCode === -105 || errCode === -137) {
      let tryHost = '';
      try { tryHost = new URL(url).hostname; } catch {}
      const safeTryUrl = (url.length > 80 ? url.slice(0, 80) + '\u2026' : url).replace(/</g, '&lt;');
      const safeHost   = tryHost.replace(/</g, '&lt;');
      const notFoundHtml =
        '<!doctype html><html><head><meta charset="utf-8"><style>' +
        'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0d0d0d;color:#ccc;' +
        'display:flex;align-items:center;justify-content:center;height:100vh;margin:0;' +
        'flex-direction:column;gap:10px;text-align:center;padding:0 20px;box-sizing:border-box;}' +
        '.ico{font-size:52px;margin-bottom:4px;user-select:none;}' +
        'h2{color:#fff;font-size:22px;margin:0;font-weight:700;letter-spacing:-.02em;}' +
        '.sub{font-size:13px;color:#666;margin:0;max-width:380px;line-height:1.6;}' +
        '.url{font-size:11.5px;color:#444;margin-top:2px;word-break:break-all;max-width:440px;}' +
        '.btns{display:flex;gap:8px;margin-top:14px;}' +
        'button{padding:9px 20px;border-radius:9px;border:1px solid rgba(255,255,255,.1);' +
        'background:rgba(255,255,255,.06);color:#ccc;cursor:pointer;font-size:13px;font-family:inherit;transition:background .12s;}' +
        'button:hover{background:rgba(255,255,255,.12);}' +
        '</style></head><body>' +
        '<div class="ico">:/</div>' +
        '<h2>Oops.. We can\'t find that site&nbsp;:/</h2>' +
        '<p class="sub">' + (safeHost ? '<strong>' + safeHost + '</strong> could not be found. Check the address for typos or try again later.' : 'This address could not be found. Check the URL and try again.') + '</p>' +
        '<p class="url">' + safeTryUrl + '</p>' +
        '<div class="btns"><button onclick="history.back()">← Go back</button><button onclick="location.reload()">Try again</button></div>' +
        '</body></html>';
      wc.executeJavaScript('document.open();document.write(' + JSON.stringify(notFoundHtml) + ');document.close()').catch(() => {});
      return;
    }

    // Blocked by ad blocker / client → show blocked page with "Continue anyway"
    if (errCode === -334) {
      let blockedHost = '';
      try { blockedHost = new URL(url).hostname; } catch {}
      const safeBlockedUrl  = (url.length > 80 ? url.slice(0, 80) + '\u2026' : url).replace(/</g, '&lt;');
      const safeBlockedHost = blockedHost.replace(/</g, '&lt;');
      const blockedHtml =
        '<!doctype html><html><head><meta charset="utf-8"><style>' +
        'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0d0d0d;color:#ccc;' +
        'display:flex;align-items:center;justify-content:center;height:100vh;margin:0;' +
        'flex-direction:column;gap:10px;text-align:center;padding:0 20px;box-sizing:border-box;}' +
        '.shield{width:56px;height:56px;background:rgba(0,212,200,.08);border:1.5px solid rgba(0,212,200,.22);' +
        'border-radius:14px;display:flex;align-items:center;justify-content:center;margin-bottom:4px;}' +
        'h2{color:#fff;font-size:22px;margin:0;font-weight:700;letter-spacing:-.02em;}' +
        '.tag{display:inline-block;padding:3px 10px;border-radius:100px;background:rgba(0,212,200,.1);' +
        'color:#00d4c8;font-size:10.5px;font-weight:600;letter-spacing:.04em;margin-top:2px;}' +
        '.sub{font-size:12.5px;color:#666;margin:6px 0 0;max-width:400px;line-height:1.65;}' +
        '.host{font-size:13px;color:#888;font-weight:600;margin-top:4px;}' +
        '.url{font-size:10.5px;color:#333;margin-top:2px;word-break:break-all;max-width:440px;}' +
        '.btns{display:flex;gap:8px;margin-top:16px;}' +
        'button{padding:9px 20px;border-radius:9px;border:1px solid rgba(255,255,255,.1);' +
        'background:rgba(255,255,255,.06);color:#ccc;cursor:pointer;font-size:13px;font-family:inherit;transition:background .12s;}' +
        'button:hover{background:rgba(255,255,255,.12);}' +
        '.cont{background:rgba(0,212,200,.1);border-color:rgba(0,212,200,.25);color:#00d4c8;}' +
        '.cont:hover{background:rgba(0,212,200,.18);}' +
        '</style></head><body>' +
        '<div class="shield"><svg width="26" height="26" viewBox="0 0 26 26" fill="none"><path d="M13 2L3 6v7c0 5.5 4 9 10 10.5C19 22 23 18.5 23 13V6L13 2Z" stroke="#00d4c8" stroke-width="1.4" stroke-linejoin="round"/><path d="M9 13l3 3 5-6" stroke="#00d4c8" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></div>' +
        '<h2>This site has been blocked</h2>' +
        '<span class="tag">Protected by Lander</span>' +
        '<p class="sub">This site has been identified as a known tracker, ad network, or potentially harmful domain. Lander Browser blocked it to protect your privacy.</p>' +
        '<p class="host">' + (safeBlockedHost || safeBlockedUrl) + '</p>' +
        '<div class="btns">' +
        '<button onclick="history.back()">← Go back</button>' +
        '<button class="cont" onclick="rawContinue()">Continue anyway</button>' +
        '</div>' +
        '<script>function rawContinue(){' +
        'window.location.href=\'raw-bypass://?h=' + encodeURIComponent(blockedHost) + '&u=' + encodeURIComponent(url) + '\';' +
        '}<\/script>' +
        '</body></html>';
      wc.executeJavaScript('document.open();document.write(' + JSON.stringify(blockedHtml) + ');document.close()').catch(() => {});
      return;
    }

    // All other errors → generic error page
    const safeUrl  = (url.length > 80 ? url.slice(0, 80) + '\u2026' : url).replace(/</g, '&lt;');
    const safeCode = String(errDesc || 'ERR_FAILED').replace(/</g, '&lt;');
    const errHtml  =
      '<!doctype html><html><head><meta charset="utf-8"><style>' +
      'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0d0d0d;color:#ccc;' +
      'display:flex;align-items:center;justify-content:center;height:100vh;margin:0;' +
      'flex-direction:column;gap:12px;text-align:center;padding:0 20px;box-sizing:border-box;}' +
      'h2{color:#fff;font-size:20px;margin:0;font-weight:700;}' +
      'p{font-size:13px;color:#666;margin:0;max-width:420px;line-height:1.6;}' +
      'code{font-size:11px;color:#444;margin-top:4px;}' +
      'button{margin-top:10px;padding:9px 22px;border-radius:9px;border:1px solid rgba(255,255,255,.1);' +
      'background:rgba(255,255,255,.07);color:#ccc;cursor:pointer;font-size:13px;font-family:inherit;}' +
      'button:hover{background:rgba(255,255,255,.13);}' +
      '</style></head><body>' +
      '<svg width="40" height="40" viewBox="0 0 40 40" fill="none">' +
      '<circle cx="20" cy="20" r="19" stroke="rgba(255,255,255,.12)" stroke-width="2"/>' +
      '<path d="M20 12v10M20 28v1" stroke="#555" stroke-width="2.2" stroke-linecap="round"/>' +
      '</svg>' +
      '<h2>Can\'t reach this page</h2>' +
      '<p>' + safeUrl + '</p>' +
      '<code>' + safeCode + '</code>' +
      '<button onclick="history.back()">Go back</button>' +
      '</body></html>';
    wc.executeJavaScript('document.open();document.write(' + JSON.stringify(errHtml) + ');document.close()').catch(() => {});
  });

  wc.on('page-title-updated', (_, title) => {
    tab.title = title || 'Untitled';
    send('tab:update', tabData(tab));
  });

  wc.on('page-favicon-updated', (_, favs) => {
    // Only accept valid http/https/file URLs — data: URIs are massive, chrome:// won't load in renderer
    const validFav = (favs || []).find(f => /^https?:\/\//i.test(f) || /^file:\/\//i.test(f));
    // Don't clear an existing favicon when SPA navigation temporarily emits empty favicons
    if (!validFav) return;
    tab.favicon = validFav;
    send('tab:update', tabData(tab));
    if (id === activeId) send('nav:state', navData(tab));
  });

  wc.on('did-navigate', (_, u) => {
    const newUrl = normalizeUrl(u);
    // Only clear favicon on cross-origin navigation — same-origin SPAs (TikTok, YouTube)
    // may not re-fire page-favicon-updated so clearing would leave the tab without an icon.
    if (tab.favicon) {
      try {
        if (new URL(tab.url || '').origin !== new URL(newUrl || '').origin) tab.favicon = null;
      } catch { tab.favicon = null; }
    }
   tab.url     = newUrl;
    tab.blocked = 0;
    send('tab:update', tabData(tab));
    if (id === activeId) {
      // Reset panel clip immediately so the page loads at full BV width
      if (panelClipX > 0) { panelClipX = 0; try { setBounds(tab.bv); } catch {} }
      send('nav:state', navData(tab));
      // Also close uBlock Origin popup if open
      if (uboPopupWin && !uboPopupWin.isDestroyed()) {
        uboPopupWin.close();
        uboPopupWin = null;
      }
      // Close all panel popups on navigation
      Object.values(_panelPopups).forEach(e => {
        if (e.win && !e.win.isDestroyed()) { try { e.win.close(); } catch {} }
        e.win = null; e.relOffset = null;
      });
    }
  });

  wc.on('did-navigate-in-page', (_, u) => {
    tab.url = normalizeUrl(u);
    send('tab:update', tabData(tab));
    if (id === activeId) {
      send('nav:state', navData(tab));
      // Close uBlock Origin popup on SPA navigation too
      if (uboPopupWin && !uboPopupWin.isDestroyed()) {
        uboPopupWin.close();
        uboPopupWin = null;
      }
      // Close all panel popups on SPA navigation too
      Object.values(_panelPopups).forEach(e => {
        if (e.win && !e.win.isDestroyed()) { try { e.win.close(); } catch {} }
        e.win = null; e.relOffset = null;
      });
    }
    // Re-inject yt-ad add-on on YouTube SPA navigation if user has it enabled.
    // Skip Shorts — the ad-skip logic interferes with Shorts video playback.
    if (/youtube\.com/i.test(u) && settings.extensions?.['yt-ad'] && !/\/shorts\//i.test(u)) {
      wc.executeJavaScript(YT_AD_SKIP).catch(() => {});
    }
  });

  wc.on('found-in-page', (_, result) => {
    send('find:result', { active: result.activeMatchOrdinal, total: result.matches });
  });

  const target = resolveUrl(url);
  if (target !== 'newtab') {
    tab.url = target; // pre-set so activateTab sees a real URL and attaches the BV
    wc.loadURL(target);
  }
  // For newtab, BV stays empty — the HTML newtab-layer in index.html shows instead

  send('tab:open', tabData(tab));
  if (activate) activateTab(id);
  return id;
}

// ── Tab close ─────────────────────────────────────────────────────────────────
function closeTab(id) {
  const tab = tabMap.get(id);
  if (!tab) return;
  tab.snapshot = null; // free JPEG memory immediately
  try { win.removeBrowserView(tab.bv); } catch {}
  try {
    const wc = tab.bv.webContents;
    if (wc && !wc.isDestroyed()) {
      // Stop any playing audio/media before destroying
      wc.setAudioMuted(true);
      wc.stop();
      wc.removeAllListeners();
      wcIdMap.delete(wc.id);
      wc.destroy();
    }
  } catch {}
  const closedGroupId = tab.groupId;
  tabMap.delete(id);
  send('tab:close', id);
  // Clean up empty groups
  if (closedGroupId && groupMap.has(closedGroupId)) {
    const stillHasTabs = [...tabMap.values()].some(t => t.groupId === closedGroupId);
    if (!stillHasTabs) { groupMap.delete(closedGroupId); sendGroupsUpdate(); }
  }
  if (activeId === id) {
    const keys = [...tabMap.keys()];
    if (keys.length) activateTab(keys[keys.length - 1]);
    else             createTab('newtab', true);
  }
}

// ── Zoom ──────────────────────────────────────────────────────────────────────
function setZoom(id, fn) {
  const t = tabMap.get(id);
  if (!t) return;
  t.zoom = Math.round(fn(t.zoom || 1) * 10) / 10;
  t.bv.webContents.setZoomFactor(t.zoom);
  send('zoom:current', t.zoom);
}

// ── uBlock Origin integration ─────────────────────────────────────────────────
let uboExtId      = null;
let uboExtDir     = null;
let uboPopupWin   = null;
let _uboPendingCoords = null;
let _uboRelOffset = null; // {x,y} popup position relative to main window
let _isOscillating   = false; // true while setPosition-based oscillation runs

// ── Close confirm popup ───────────────────────────────────────────────────────
let _closeConfirmWin = null;

// ── Theme broadcast to all popups ─────────────────────────────────────────────
function _getThemeVars() {
  if (!win || win.isDestroyed()) return null;
  return win.webContents.executeJavaScript(`(function(){
    const s = getComputedStyle(document.body);
    const g = v => s.getPropertyValue(v).trim();
    return { bg0:g('--bg0'),bg1:g('--bg1'),bg2:g('--bg2'),bg3:g('--bg3'),bg4:g('--bg4'),bg5:g('--bg5'),
             ln:g('--ln'),ln2:g('--ln2'),t0:g('--t0'),t1:g('--t1'),t2:g('--t2'),t3:g('--t3'),t4:g('--t4'),
             acc:g('--acc'),'acc-raw':g('--acc-raw'),accRaw:g('--acc-raw'),
             f:g('--f') || "'Geist', ui-sans-serif, system-ui, -apple-system, sans-serif" };
  })()`).catch(() => null);
}
function _sendThemeToPopup(popupWin) {
  if (!popupWin || popupWin.isDestroyed()) return;
  _getThemeVars().then(theme => {
    if (theme && popupWin && !popupWin.isDestroyed()) {
      popupWin.webContents.send('popup:theme', theme);
    }
  });
}
function _broadcastThemeToPopups() {
  _getThemeVars().then(theme => {
    if (!theme) return;
    if (uboPopupWin && !uboPopupWin.isDestroyed()) uboPopupWin.webContents.send('popup:theme', theme);
    if (_closeConfirmWin && !_closeConfirmWin.isDestroyed()) _closeConfirmWin.webContents.send('popup:theme', theme);
    if (_sidebarAddWin && !_sidebarAddWin.isDestroyed()) _sidebarAddWin.webContents.send('popup:theme', theme);
    Object.values(_panelPopups).forEach(e => {
      if (e.win && !e.win.isDestroyed()) e.win.webContents.send('popup:theme', theme);
    });
    // Sync incognito window so it always matches the main window theme
    if (incognitoWin && !incognitoWin.isDestroyed()) incognitoWin.webContents.send('popup:theme', theme);
  });
}

// Spawn helper — returns { code, stderr }
function _spawnAsync(cmd, args, opts) {
  return new Promise((resolve) => {
    const proc = spawn(cmd, args, { stdio: ['ignore', 'ignore', 'pipe'], ...opts });
    let stderr = '';
    if (proc.stderr) proc.stderr.on('data', d => stderr += d.toString());
    proc.on('error', e => resolve({ code: -1, stderr: e.message }));
    proc.on('close', code => resolve({ code, stderr }));
  });
}

// Fetch the latest uBO chromium zip URL via GitHub API then download with curl
function _uboFetchLatestUrl() {
  return new Promise((resolve, reject) => {
    const req = https.get(
      'https://api.github.com/repos/gorhill/uBlock/releases/latest',
      { headers: { 'User-Agent': 'lander-browser', 'Accept': 'application/vnd.github+json' } },
      (res) => {
        let body = '';
        res.on('data', d => body += d);
        res.on('end', () => {
          try {
            const assets = JSON.parse(body).assets || [];
            const asset  = assets.find(a => /chromium\.zip$/i.test(a.name));
            if (!asset) { reject(new Error('chromium.zip asset not found in latest release')); return; }
            resolve(asset.browser_download_url);
          } catch (e) { reject(new Error('GitHub API parse error: ' + e.message)); }
        });
      }
    );
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('GitHub API timeout')); });
  });
}

async function _uboDownload(dest) {
  const url = await _uboFetchLatestUrl();
  const curlBin = process.platform === 'win32' ? 'curl.exe' : 'curl';
  const { code, stderr } = await _spawnAsync(curlBin, [
    '-L', '--fail', '--silent', '--show-error', '-o', dest, url,
  ]);
  if (code !== 0 || !fs.existsSync(dest)) throw new Error(stderr || `curl exited ${code}`);
}

// Extract zip using platform-native tool
async function _uboExtract(zipPath, destDir) {
  if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
  if (process.platform === 'win32') {
    const { code, stderr } = await _spawnAsync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
      `Expand-Archive -Force -LiteralPath "${zipPath}" -DestinationPath "${destDir}"`,
    ]);
    if (code !== 0) throw new Error(stderr || `Expand-Archive exited ${code}`);
    return;
  }
  const { code, stderr } = await _spawnAsync('unzip', ['-o', zipPath, '-d', destDir]);
  if (code > 1) throw new Error(stderr || `unzip exited ${code}`); // code 1 = warnings, ok
}

// Recursively copy a directory
function _copyDirSync(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name), d = path.join(dest, entry.name);
    if (entry.isDirectory()) _copyDirSync(s, d);
    else fs.copyFileSync(s, d);
  }
}

// Find the folder that contains manifest.json (handles root or one-level-deep layout)
function _findExtDir(base) {
  if (fs.existsSync(path.join(base, 'manifest.json'))) return base;
  try {
    for (const name of fs.readdirSync(base)) {
      const sub = path.join(base, name);
      if (fs.statSync(sub).isDirectory() && fs.existsSync(path.join(sub, 'manifest.json'))) return sub;
    }
  } catch {}
  return null;
}

async function setupUBO() {
  const ses = session.fromPartition('persist:main');
  const uboFinal = path.join(app.getPath('userData'), 'extensions', 'ublock');

  // Wipe incomplete installs — must have both manifest.json AND popup.html
  if (fs.existsSync(uboFinal)) {
    const hasManifest = fs.existsSync(path.join(uboFinal, 'manifest.json'));
    const hasPopup    = hasManifest && (() => {
      try {
        const mf = JSON.parse(fs.readFileSync(path.join(uboFinal, 'manifest.json'), 'utf8'));
        const p  = (mf.browser_action || mf.action || {}).default_popup || 'popup.html';
        return fs.existsSync(path.join(uboFinal, p));
      } catch { return false; }
    })();
    if (!hasManifest || !hasPopup) {
      console.log('[uBO] Incomplete install detected, wiping and re-downloading');
      try { fs.rmSync(uboFinal, { recursive: true, force: true }); } catch {}
    }
  }

  let extDir = _findExtDir(uboFinal);

  if (!extDir) {
    const tmpZip  = path.join(app.getPath('temp'), 'ublock0-setup.zip');
    const tmpDest = path.join(app.getPath('temp'), 'ublock0-extract');

    try { fs.rmSync(tmpDest, { recursive: true, force: true }); } catch {}
    try { fs.unlinkSync(tmpZip); } catch {}

    try {
      await _uboDownload(tmpZip);
    } catch (e) {
      console.error('[uBO] download failed:', e.message);
      send('toast', `uBlock Origin download failed: ${e.message}`);
      return;
    }

    try {
      await _uboExtract(tmpZip, tmpDest);
    } catch (e) {
      console.error('[uBO] extract failed:', e.message);
      send('toast', `uBlock Origin extract failed: ${e.message}`);
      try { fs.unlinkSync(tmpZip); } catch {}
      return;
    }

    const found = _findExtDir(tmpDest);
    if (!found) {
      console.error('[uBO] manifest.json not found after extraction');
      send('toast', 'uBlock Origin: unexpected zip structure');
      try { fs.rmSync(tmpDest, { recursive: true, force: true }); fs.unlinkSync(tmpZip); } catch {}
      return;
    }

    _copyDirSync(found, uboFinal);
    try { fs.rmSync(tmpDest, { recursive: true, force: true }); } catch {}
    try { fs.unlinkSync(tmpZip); } catch {}
    extDir = uboFinal;
  }

  // Strip permissions Electron doesn't implement to silence load warnings.
  // We write to a patched copy so the original download is never touched.
  const _UNSUPPORTED_PERMS = new Set(['contextMenus', 'privacy', 'webNavigation']);
  try {
    const mfPath = path.join(extDir, 'manifest.json');
    const mf = JSON.parse(fs.readFileSync(mfPath, 'utf8'));
    if ((mf.permissions || []).some(p => _UNSUPPORTED_PERMS.has(p))) {
      mf.permissions = (mf.permissions || []).filter(p => !_UNSUPPORTED_PERMS.has(p));
      fs.writeFileSync(mfPath, JSON.stringify(mf, null, 2));
    }
  } catch {}

  try {
    const ext = await ses.extensions.loadExtension(extDir, { allowFileAccess: true });
    uboExtId  = ext.id;
    uboExtDir = extDir;
    try { await session.fromPartition('incognito').extensions.loadExtension(extDir, { allowFileAccess: true }); } catch {}
    if (_uboPendingCoords) {
      const c = _uboPendingCoords; _uboPendingCoords = null;
      _uboOpenPopup(c);
    }
  } catch (e) {
    console.error('[uBO] loadExtension failed:', e.message);
    send('toast', `uBlock Origin failed to load: ${e.message}`);
  }
}

function _uboOpenPopup({ x, y }) {
  if (uboPopupWin && !uboPopupWin.isDestroyed()) { uboPopupWin.focus(); return; }

  const { screen } = require('electron');
  const wa  = screen.getDisplayNearestPoint(screen.getCursorScreenPoint()).workArea;
  const [wx, wy] = win.getPosition();

  const pw = 336; // 320px card + 8px margin each side
  const ph = 10;  // grows to content after load
  let px = Math.round(wx + x) - Math.floor(pw / 2);
  let py = Math.round(wy + y) + 6;
  if (px + pw > wa.x + wa.width)  px = wa.x + wa.width  - pw - 8;
  if (px < wa.x)                  px = wa.x + 8;
  if (py + ph > wa.y + wa.height) py = Math.round(wy + y) - 300 - 6;
  if (py < wa.y)                  py = wa.y + 4;

  _uboRelOffset = { x: px - wx, y: py - wy };

  uboPopupWin = new BrowserWindow({
    x: px, y: py,
    width: pw, height: ph,
    frame: false,
    resizable: false,
    show: false,
    alwaysOnTop: false,
    skipTaskbar: true,
    transparent: true, // <-- CHANGED TO TRUE
    backgroundColor: '#00000000', // <-- CHANGED TO FULLY TRANSPARENT
    hasShadow: false,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
  });
  uboPopupWin.loadFile(path.join(__dirname, 'assets', 'ubo-popup.html'));
  uboPopupWin.webContents.on('did-finish-load', () => {
    uboPopupWin?.webContents.executeJavaScript('document.body.scrollHeight')
      .then(h => {
        if (uboPopupWin && !uboPopupWin.isDestroyed()) {
          uboPopupWin.setSize(pw, Math.max(180, h + 2));
          uboPopupWin.show();
        }
      }).catch(() => { uboPopupWin?.show(); });
  });
  uboPopupWin.on('move', () => {
    if (_isOscillating || !win || win.isDestroyed() || !uboPopupWin || uboPopupWin.isDestroyed()) return;
    try {
      const [wx2, wy2] = win.getPosition();
      const [ux, uy]   = uboPopupWin.getPosition();
      _uboRelOffset = { x: ux - wx2, y: uy - wy2 };
    } catch {}
  });
  uboPopupWin.webContents.on('will-navigate', (e, url) => { if (!url.startsWith('file:')) e.preventDefault(); });
  uboPopupWin.on('closed', () => { uboPopupWin = null; _uboRelOffset = null; });
}

ipcMain.handle('ubo:get-stats', async () => {
  const tab = tabMap.get(activeId);
  let domain = '';
  if (tab?.url && tab.url !== 'newtab') {
    try { domain = new URL(tab.url).hostname.replace(/^www\./, ''); } catch {}
  }
  const paused = domain ? (userWhitelist || []).some(d => domain === d || domain.endsWith('.' + d)) : false;
  // Read live CSS theme variables from main window so popup matches app palette
  let theme = {};
  try {
    // Theme vars are overridden on body (e.g. body.theme-light { --bg0:... })
    // so getComputedStyle(body) returns the active theme values.
    theme = await win.webContents.executeJavaScript(`(function(){
      const s = getComputedStyle(document.body);
      const g = v => s.getPropertyValue(v).trim();
      return { bg0:g('--bg0'), bg1:g('--bg1'), bg2:g('--bg2'),
               acc:g('--acc'), accRaw:g('--acc-raw'),
               ln:g('--ln'), t0:g('--t0'), t1:g('--t1'), t2:g('--t2') };
    })()`);
  } catch {}
  return {
    domain,
    pageBlocked:    tab?.blocked    || 0,
    sessionBlocked: tab?.blocked    || 0,
    totalBlocked,
    paused,
    theme,
  };
});

ipcMain.on('ubo:reload-tab', () => {
  const tab = tabMap.get(activeId);
  if (tab?.bv && !tab.bv.webContents.isDestroyed()) tab.bv.webContents.reload();
});

// ── Browser-switch popup ───────────────────────────────────────────────────────
// Shown when user navigates to a competitor browser site. Opens as a separate
// frameless window positioned top-right of the main window so it never overlays
// or blocks the page being loaded (unlike the old chrome:intercept IPC approach).
let _browserSwitchWin = null;
let _browserSwitchRelOffset = null;

function _showBrowserSwitchPopup(browser, host) {
  if (_browserSwitchWin && !_browserSwitchWin.isDestroyed()) {
    _browserSwitchWin.webContents.send('browser-switch:info', { host, browser });
    _browserSwitchWin.focus();
    return;
  }
  const { screen } = require('electron');
  const [wx, wy] = win ? win.getPosition() : [0, 0];
  const [ww]     = win ? win.getSize()     : [1280];
  const wa       = screen.getDisplayNearestPoint({ x: wx, y: wy }).workArea;
  const pw       = 356;
  let px = wx + ww - pw - 12;
  let py = wy + 120;
  if (px + pw > wa.x + wa.width) px = wa.x + wa.width - pw - 8;
  if (px < wa.x) px = wa.x + 8;
  if (py < wa.y) py = wa.y + 4;

  _browserSwitchRelOffset = { x: px - wx, y: py - wy };

  _browserSwitchWin = new BrowserWindow({
    x: px, y: py, width: pw, height: 10,
    frame: false, resizable: false, show: false,
    skipTaskbar: true, alwaysOnTop: true,
    transparent: true, backgroundColor: '#00000000', hasShadow: false,
    webPreferences: { nodeIntegration: true, contextIsolation: false },
  });
  _browserSwitchWin.loadFile(path.join(__dirname, 'assets', 'browser-switch.html'));
  _browserSwitchWin.webContents.on('did-finish-load', () => {
    if (!_browserSwitchWin || _browserSwitchWin.isDestroyed()) return;
    _sendThemeToPopup(_browserSwitchWin);
    _browserSwitchWin.webContents.send('browser-switch:info', { host, browser });
    setTimeout(() => {
      if (!_browserSwitchWin || _browserSwitchWin.isDestroyed()) return;
      _browserSwitchWin.webContents.executeJavaScript('document.body.scrollHeight').then(h => {
        if (_browserSwitchWin && !_browserSwitchWin.isDestroyed()) {
          _browserSwitchWin.setSize(pw, Math.min(480, Math.max(200, h)));
          _browserSwitchWin.show();
        }
      }).catch(() => { _browserSwitchWin?.show(); });
    }, 60);
  });
  _browserSwitchWin.on('move', () => {
    if (_isOscillating || !win || win.isDestroyed() || !_browserSwitchWin || _browserSwitchWin.isDestroyed()) return;
    try {
      const [wx2, wy2] = win.getPosition();
      const [nx, ny] = _browserSwitchWin.getPosition();
      _browserSwitchRelOffset = { x: nx - wx2, y: ny - wy2 };
    } catch {}
  });
  _browserSwitchWin.webContents.on('will-navigate', (ev, u) => { if (!u.startsWith('file:')) ev.preventDefault(); });
  _browserSwitchWin.on('closed', () => { _browserSwitchWin = null; _browserSwitchRelOffset = null; });
}

// ── Generic panel popup windows (same approach as UBO) ────────────────────────
// Each panel opens as a separate frameless BrowserWindow instead of an inline
// panel div, so the BV is never parked and site interaction is never blocked.
// Notes, Calculator, Downloads, and all toolbar popups use this unified system.
const _panelPopups = {};  // name → { win, relOffset }

function _openPanelPopup(name, htmlFile, pw, phInit, coords, opts) {
  const entry = _panelPopups[name] || (_panelPopups[name] = { win: null, relOffset: null });
  if (entry.win && !entry.win.isDestroyed()) { entry.win.focus(); return; }

  const { screen } = require('electron');
  const wa = screen.getDisplayNearestPoint(screen.getCursorScreenPoint()).workArea;
  const [wx, wy] = win ? win.getPosition() : [0, 0];

  let px = coords ? Math.round(wx + coords.x) - Math.floor(pw / 2) : wa.x + Math.floor((wa.width - pw) / 2);
  let py = coords ? Math.round(wy + coords.y) + 6 : wa.y + Math.floor((wa.height - phInit) / 2);
  if (px + pw > wa.x + wa.width)  px = wa.x + wa.width - pw - 8;
  if (px < wa.x)                  px = wa.x + 8;
  if (py + phInit > wa.y + wa.height) py = wa.y + wa.height - phInit - 8;
  if (py < wa.y)                  py = wa.y + 4;

  entry.relOffset = { x: px - wx, y: py - wy };

  entry.win = new BrowserWindow({
    x: px, y: py, width: pw, height: phInit,
    frame: false, resizable: !!opts?.resizable, show: false,
    skipTaskbar: true, alwaysOnTop: false,
    transparent: true, backgroundColor: '#00000000', hasShadow: false,
    webPreferences: { nodeIntegration: true, contextIsolation: false },
  });

  entry.win.loadFile(path.join(__dirname, 'assets', htmlFile));

  entry.win.webContents.on('did-finish-load', () => {
    if (!entry.win || entry.win.isDestroyed()) return;
    _sendThemeToPopup(entry.win);
    if (opts?.onLoad) opts.onLoad(entry.win);
    // Auto-resize to content height
    const maxH = opts?.maxHeight || 520;
    const minH = opts?.minHeight || 120;
    const doMeasure = () => {
      if (!entry.win || entry.win.isDestroyed()) return;
      entry.win.webContents.executeJavaScript('document.body.scrollHeight').then(h => {
        if (entry.win && !entry.win.isDestroyed()) {
          // phInit<=20 = dynamic popup: body already includes 16px padding, no extra pad needed.
          // phInit>20  = fixed-size popup: add 40px to account for card height => body height conversion.
          const extraPad = phInit <= 20 ? 0 : 40;
          const actualH = Math.min(maxH, Math.max(minH, h + extraPad));
          entry.win.setSize(pw, actualH);
          // Flip popup above the button if it extends below the main window's bottom edge
          if (win && !win.isDestroyed()) {
            try {
              const [wx2, wy2] = win.getPosition();
              const [, wh2]   = win.getContentSize();
              const [popX, popY] = entry.win.getPosition();
              if (popY + actualH > wy2 + wh2) {
                const newY = Math.max(wy2 + 4, Math.round(wy2 + (coords?.y || 42)) - actualH - 8);
                entry.win.setPosition(popX, newY);
              }
            } catch {}
          }
          entry.win.show();
        }
      }).catch(() => { entry.win?.show(); });
    };
    // If popup has dynamic onLoad content (e.g. dl:list), wait 80ms for the renderer
    // to process the IPC message before measuring — prevents showing at wrong size.
    if (opts?.onLoad) setTimeout(doMeasure, 80);
    else doMeasure();
  });

  entry.win.on('move', () => {
    if (_isOscillating || !win || win.isDestroyed() || !entry.win || entry.win.isDestroyed()) return;
    try {
      const [wx2, wy2] = win.getPosition();
      const [nx, ny] = entry.win.getPosition();
      entry.relOffset = { x: nx - wx2, y: ny - wy2 };
    } catch {}
  });

  entry.win.webContents.on('will-navigate', (e, url) => { if (!url.startsWith('file:')) e.preventDefault(); });
  entry.win.on('closed', () => { entry.win = null; entry.relOffset = null; });
}

// Toggle helpers for each panel popup
function _togglePanelPopup(name, htmlFile, pw, ph, coords, opts) {
  const entry = _panelPopups[name];
  if (entry?.win && !entry.win.isDestroyed()) {
    entry.win.close(); entry.win = null; return;
  }
  _openPanelPopup(name, htmlFile, pw, ph, coords, opts);
}

ipcMain.on('bm:show-popup', (_, c) => _togglePanelPopup('bm', 'bookmarks-popup.html', 336, 460, c));
ipcMain.on('limiter:show-popup', (_, c) => _togglePanelPopup('limiter', 'limiter-popup.html', 336, 10, c, { maxHeight: 480 }));
ipcMain.on('poison:show-popup', (_, c) => _togglePanelPopup('poison', 'poison-popup.html', 336, 10, c, { maxHeight: 620 }));
ipcMain.on('pw:show-popup', (_, c) => _togglePanelPopup('pw', 'passwords-popup.html', 316, 440, c));
ipcMain.on('geo:show-popup', (_, c) => _togglePanelPopup('geo', 'geo-popup.html', 336, 10, c, { maxHeight: 520 }));
ipcMain.on('ytdlp:show-popup', (_, c) => _togglePanelPopup('ytdlp', 'ytdlp-popup.html', 380, 10, c, { maxHeight: 580 }));
ipcMain.on('notes:show-popup', (_, c) => _togglePanelPopup('notes', 'notes.html', 280, 400, c, { resizable: true, maxHeight: 520 }));
ipcMain.on('calc:show-popup', (_, c) => _togglePanelPopup('calc', 'calculator.html', 264, 10, c, { maxHeight: 400 }));
ipcMain.on('default-browser:show-popup', (_, c) => _togglePanelPopup('defaultBrowser', 'default-browser-popup.html', 280, 10, c, { maxHeight: 220 }));
ipcMain.on('dl:show-popup', (_, c) => _togglePanelPopup('dl', 'downloads-popup.html', 336, 10, c, {
  maxHeight: 460,
  onLoad: (w) => { w.webContents.send('dl:list', downloads); },
}));
ipcMain.on('media:show-popup', (_, c) => _togglePanelPopup('media', 'media-popup.html', 336, 10, c, {
  maxHeight: 480,
  onLoad: (w) => { w.webContents.send('audio:update', _getAudioTabs()); },
}));
ipcMain.on('browser-promo:show', () => {
  _togglePanelPopup('browserPromo', 'browser-promo-popup.html', 380, 180, null, { maxHeight: 280 });
});
ipcMain.on('browser-switch:close', () => {
  if (_browserSwitchWin && !_browserSwitchWin.isDestroyed()) { try { _browserSwitchWin.close(); } catch {} }
  _browserSwitchWin = null; _browserSwitchRelOffset = null;
});

// ── Omnibox popup window ───────────────────────────────────────────────────────
// Opens a separate frameless window at the address bar position so focusing the
// address bar never affects the active BrowserView (fixes TikTok/SPA freeze).
ipcMain.on('omnibox:open', (_, { relX, relY, w, url, history }) => {
  const entry = _panelPopups['omnibox'] || (_panelPopups['omnibox'] = { win: null, relOffset: null });
  if (entry.win && !entry.win.isDestroyed()) { entry.win.focus(); return; }
  if (!win || win.isDestroyed()) return;

  const [wx, wy] = win.getPosition();
  const [ww]     = win.getSize();
  const pw  = Math.max(Math.min(w || 600, ww - 60), 400);
  let   px  = Math.round(wx + (relX || ww / 2) - pw / 2);
  const py  = Math.round(wy + (relY || CHROME_H - 10));

  const { screen: _scr } = require('electron');
  const wa = _scr.getDisplayNearestPoint({ x: wx, y: wy }).workArea;
  if (px + pw > wa.x + wa.width)  px = wa.x + wa.width - pw - 8;
  if (px < wa.x)                  px = wa.x + 8;

  entry.relOffset = { x: px - wx, y: py - wy };

  entry.win = new BrowserWindow({
    x: px, y: py, width: pw, height: 36,
    frame: false, resizable: false, show: false,
    skipTaskbar: true, alwaysOnTop: false,
    transparent: true, backgroundColor: '#00000000', hasShadow: false,
    webPreferences: { nodeIntegration: true, contextIsolation: false },
  });

  entry.win.loadFile(path.join(__dirname, 'assets', 'omnibox-popup.html'));

  entry.win.webContents.on('did-finish-load', () => {
    if (!entry.win || entry.win.isDestroyed()) return;
    _sendThemeToPopup(entry.win);
    const tab = tabMap.get(activeId);
    entry.win.webContents.send('omnibox:init', {
      url:     url || (tab ? tab.url : ''),
      history: history || [],
    });
    entry.win.show();
    entry.win.focus();
  });

  entry.win.on('move', () => {
    if (_isOscillating || !win || win.isDestroyed() || !entry.win || entry.win.isDestroyed()) return;
    try {
      const [wx2, wy2] = win.getPosition();
      const [nx, ny]   = entry.win.getPosition();
      entry.relOffset = { x: nx - wx2, y: ny - wy2 };
    } catch {}
  });

  entry.win.webContents.on('will-navigate', (e, u) => { if (!u.startsWith('file:')) e.preventDefault(); });
  entry.win.on('closed', () => { entry.win = null; entry.relOffset = null; });
});

ipcMain.on('omnibox:close', () => {
  const entry = _panelPopups['omnibox'];
  if (entry?.win && !entry.win.isDestroyed()) { try { entry.win.close(); } catch {} }
  if (entry) { entry.win = null; entry.relOffset = null; }
});

ipcMain.on('omnibox:resize', (_, h) => {
  const entry = _panelPopups['omnibox'];
  if (!entry?.win || entry.win.isDestroyed()) return;
  const newH = Math.max(48, Math.min(h + 16, 480));
  entry.win.setSize(entry.win.getSize()[0], newH);
});

// ── Omnibox focus guard ────────────────────────────────────────────────────────
// When the user clicks the address bar, suppress blur events in the active BV
// so SPAs (TikTok, YouTube etc.) don't pause video or reduce quality.
ipcMain.on('omnibox:focus-start', () => {
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.bv.webContents.isDestroyed() || tab.url === 'newtab') return;
  tab.bv.webContents.executeJavaScript(`(function(){
    if (!window._rbOmniGuard) {
      window._rbOmniGuard = function(e){ e.stopImmediatePropagation(); };
      document.addEventListener('blur', window._rbOmniGuard, true);
      window.addEventListener('blur', window._rbOmniGuard, true);
      if(window.HTMLVideoElement){
        window._rbOmniPause = HTMLVideoElement.prototype.pause;
        HTMLVideoElement.prototype.pause = function(){};
      }
    }
  })()`).catch(() => {});
});
ipcMain.on('omnibox:focus-end', () => {
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.bv.webContents.isDestroyed()) return;
  tab.bv.webContents.executeJavaScript(`(function(){
    if (window._rbOmniGuard) {
      document.removeEventListener('blur', window._rbOmniGuard, true);
      window.removeEventListener('blur', window._rbOmniGuard, true);
      window._rbOmniGuard = null;
    }
    if (window._rbOmniPause && window.HTMLVideoElement) {
      HTMLVideoElement.prototype.pause = window._rbOmniPause;
      window._rbOmniPause = null;
    }
  })()`).catch(() => {});
});
ipcMain.on('media:resize', (_, h) => {
  const mp = _panelPopups.media;
  if (mp?.win && !mp.win.isDestroyed()) {
    mp.win.setSize(336, Math.min(480, Math.max(120, h)));
  }
});

ipcMain.on('ubo:show-popup', (_, coords) => {
  if (uboPopupWin && !uboPopupWin.isDestroyed()) {
    uboPopupWin.close(); uboPopupWin = null; return;
  }
  if (!uboExtId) {
    _uboPendingCoords = coords;
    send('toast', 'uBlock Origin is loading… popup will open automatically when ready');
    return;
  }
  _uboOpenPopup(coords);
});

ipcMain.on('ubo:open-page', (_, page) => {
  if (!uboExtDir) return;
  const allowed = ['dashboard.html', 'logger-ui.html'];
  const safe = allowed.find(p => page === p);
  if (!safe) return;
  const { shell } = require('electron');
  shell.openPath(path.join(uboExtDir, safe)).catch(() => {});
});

// dl:resize — sent from downloads popup to resize itself after render
ipcMain.on('dl:resize', (_, h) => {
  const dlp = _panelPopups.dl;
  if (dlp?.win && !dlp.win.isDestroyed()) {
    const bounds = dlp.win.getBounds();
    dlp.win.setSize(bounds.width, Math.min(460, Math.max(120, h)));
  }
});

// Close all panel popups (called when toolbar layout changes so popups don't sit at stale positions)
ipcMain.on('panel:close-all-popups', () => {
  Object.values(_panelPopups).forEach(e => {
    if (e.win && !e.win.isDestroyed()) { try { e.win.close(); } catch {} }
    e.win = null; e.relOffset = null;
  });
  if (uboPopupWin && !uboPopupWin.isDestroyed()) { try { uboPopupWin.close(); } catch {} }
  if (_sidebarAddWin && !_sidebarAddWin.isDestroyed()) { try { _closeSidebarAddPopup(); } catch {} }
});

// Forward download list updates to the downloads popup if it's open
ipcMain.on('dl:list:forward', (_, list) => {
  const dlp = _panelPopups.dl;
  if (dlp?.win && !dlp.win.isDestroyed()) {
    dlp.win.webContents.send('dl:list', list);
  }
});

// ── Session / ad-blocking setup ───────────────────────────────────────────────
function setupSession(ses) {
  // Tracking parameters that are pure cross-site identifiers with no functional value.
  const _TRACKING_PARAMS = new Set([
    // UTM campaign params
    'utm_source','utm_medium','utm_campaign','utm_term','utm_content','utm_id',
    'utm_source_platform','utm_creative_format','utm_marketing_tactic',
    // Facebook / Meta
    'fbclid','fb_action_ids','fb_action_types','fb_source','fb_ref','fbaid',
    // Google Ads
    'gclid','gclsrc','gbraid','wbraid','gad_source','gad_campaignid',
    // Microsoft / Bing
    'msclkid',
    // Mailchimp
    'mc_eid','mc_cid',
    // TikTok / Twitter / Snapchat / LinkedIn / others
    'ttclid','twclid','dclid','yclid','sscid','zanpid','li_fat_id','epik',
    'ScCid','scid',
    // Google Analytics
    '_ga','_gl',
    // HubSpot
    '_hsenc','_hsmi','hsa_acc','hsa_cam','hsa_grp','hsa_ad','hsa_src',
    'hsa_tgt','hsa_kw','hsa_mt','hsa_net','hsa_ver',
    // Marketo
    'mkt_tok',
    // Instagram
    'igshid',
    // Optinmonster / misc
    'oly_anon_id','oly_enc_id','rb_clickid','vero_id','vero_conv',
    // Adobe / Omniture
    's_cid','s_kwcid','ef_id',
    // Wickedreports
    'wickedid',
    // LinkedIn tracking
    'trk','trkCampaign','trkcampaign','trkInfo',
    // Impact / affiliate
    'irclickid','irgwc',
    // Klaviyo
    'kx','kl_referrer',
    // Drip
    'dc_ref',
    // Outbrain / Taboola
    'obOrigUrl','tblci',
    // General ref/origin params
    'ref','ref_src','ref_url','referrer','origin',
    // Iterable
    '_id',
    // Salesforce Pardot
    'piid','pi_ref',
    // Criteo
    'criteo_aid',
    // Quantcast
    'qclid',
    // Reddit Ads
    'rdt_cid',
  ]);

  ses.webRequest.onBeforeRequest({ urls: ['*://*/*'] }, (details, cb) => {
    const tab = tabMap.get(wcIdMap.get(details.webContentsId));
    if (!tab) return cb({});

    // Strip cross-site tracking parameters from URLs before the request is sent.
    // Runs on all navigation requests — tracking params are never legitimate for privacy.
    if (details.resourceType === 'mainFrame' || details.resourceType === 'subFrame') {
      try {
        const u = new URL(details.url);
        let stripped = false;
        for (const key of [...u.searchParams.keys()]) {
          if (_TRACKING_PARAMS.has(key)) { u.searchParams.delete(key); stripped = true; }
        }
        if (stripped) return cb({ redirectURL: u.toString() });
      } catch {}
    }

    // If user clicked "Continue anyway" for this host, skip blocking
    try {
      const _reqHost = new URL(details.url).hostname.toLowerCase();
      if (_tempBypassSet.has(_reqHost)) return cb({});
    } catch {}

    try {
      const host = new URL(details.url).hostname.toLowerCase().replace(/^www\./, '');
      // Tracker override: block these even if parent domain is whitelisted
      if (settings.adblockEnabled && TRACKER_FORCE_BLOCK.has(host)) {
        tab.blocked = (tab.blocked || 0) + 1;
        totalBlocked++;
        if (tab.id === activeId) send('blocked:update', { total: totalBlocked, session: tab.blocked });
        return cb({ cancel: true });
      }
      if (BUILTIN_WHITELIST.some(d => host === d || host.endsWith('.' + d))) return cb({});
      if (userWhitelist.some(d => host === d || host.endsWith('.' + d))) return cb({});
    } catch {}

    // Block YouTube ad-tracking/serving URLs (safe — carry no video content)
    if (YT_AD_BLOCK_PATTERNS.some(p => p.test(details.url))) {
      tab.blocked = (tab.blocked || 0) + 1;
      totalBlocked++;
      if (tab.id === activeId) send('blocked:update', { total: totalBlocked, session: tab.blocked });
      return cb({ cancel: true });
    }

    if (_shouldBlockCached(details.url, settings.adblockEnabled, settings.blockingLevel || 'moderate', details.resourceType === 'mainFrame')) {
      tab.blocked = (tab.blocked || 0) + 1;
      totalBlocked++;
      if (tab.id === activeId) send('blocked:update', { total: totalBlocked, session: tab.blocked });
      return cb({ cancel: true });
    }
    cb({});
  });

  ses.webRequest.onBeforeSendHeaders({ urls: ['*://*/*'] }, (details, cb) => {
    const h = { ...details.requestHeaders };

    // Helper: apply full Chrome UA spoof to headers object
    function _applyUA(headers) {
      headers['User-Agent'] = SPOOF_UA;
      headers['Sec-CH-UA'] = SPOOF_UA_HINTS;
      headers['Sec-CH-UA-Mobile'] = '?0';
      headers['Sec-CH-UA-Platform'] = '"Windows"';
      headers['Sec-CH-UA-Platform-Version'] = '"10.0.0"';
      headers['Sec-CH-UA-Arch'] = '"x86"';
      headers['Sec-CH-UA-Bitness'] = '"64"';
      headers['Sec-CH-UA-Full-Version'] = '"135.0.7049.85"';
      headers['Sec-CH-UA-Full-Version-List'] = '"Not_A Brand";v="8.0.0.0", "Chromium";v="135.0.7049.85", "Google Chrome";v="135.0.7049.85"';
    }

    // For whitelisted domains (Google, Spotify, TikTok, etc.) — spoof UA and return
    // immediately, leaving all other headers (Referer, Origin, Sec-Fetch-*) intact.
    // CRITICAL: This must apply even when the request comes from a popup/OAuth window
    // (which has no matching tab entry). Without this, Sec-CH-UA for Google sign-in
    // popup windows shows Electron's real brands, triggering "not secure browser".
    let isWhitelisted = false;
    try {
      const host = new URL(details.url).hostname.toLowerCase().replace(/^www\./, '');
      isWhitelisted = BUILTIN_WHITELIST.some(d => host === d || host.endsWith('.' + d));
    } catch {}

    if (isWhitelisted) {
      _applyUA(h);
      return cb({ requestHeaders: h });
    }

    // For non-whitelisted requests from popup windows / unknown webContents
    // (no matching BV tab) — skip all header modifications to avoid breaking them.
    const tab = tabMap.get(wcIdMap.get(details.webContentsId));
    if (!tab) return cb({});

    // Always send DNT and GPC — these are privacy signals, not toggleable features
    h['DNT'] = '1';
    h['Sec-GPC'] = '1';
    _applyUA(h);

    // Strip Referer on cross-origin requests — prevents full page URLs (with
    // tokens / session IDs) leaking to third-party servers.
    // For known tracker/ad domains: strip entirely (no origin leak either).
    // For general cross-site: truncate to origin-only.
    if (h['Referer']) {
      try {
        const refHost = new URL(h['Referer']).hostname;
        const reqHost = new URL(details.url).hostname.toLowerCase().replace(/^www\./, '');
        if (refHost !== new URL(details.url).hostname) {
          if (_shouldBlockCached(details.url, true, 'moderate')) {
            delete h['Referer']; // tracker — remove entirely
          } else {
            h['Referer'] = new URL(h['Referer']).origin + '/';
          }
        }
      } catch { delete h['Referer']; }
    }

    // Remove headers that can reveal the user's real IP to proxied servers
    delete h['X-Forwarded-For'];
    delete h['Via'];
    delete h['Forwarded'];

    cb({ requestHeaders: h });
  });

  // Set session-level UA so DRM license requests (Widevine/Spotify) also use spoofed UA
  ses.setUserAgent(SPOOF_UA);

  // ── Strip CSP for bypass domains — required for preload main-world spoofing ──
  // accounts.google.com and other sign-in providers set strict Content-Security-Policy
  // headers that block inline <script> injections. Our preload.js spoofing must run in
  // the page's main JS world (contextIsolation:true forces it to use <script> injection).
  // Without stripping CSP, Google's page blocks our script and keeps seeing Electron's
  // real navigator.userAgentData.brands, triggering the "app may not be secure" error.
  const _cspBypassSet = new Set([
    'google.com','googleapis.com','googleusercontent.com','gstatic.com','gmail.com',
    'accounts.google.com','youtube.com','youtu.be',
    'microsoft.com','live.com','microsoftonline.com','bing.com','msn.com','bingapis.com',
    'apple.com','appleid.apple.com',
    'facebook.com','instagram.com','fbcdn.net',
    'spotify.com','scdn.co','tiktok.com','tiktokv.com',
    'amazon.com','amazon.co.uk','amazon.de','amazon.fr','amazon.it','amazon.es','amazon.ca',
    'amazon.com.au','amazon.co.jp','amazonaws.com','amazon-adsystem.com','media-amazon.com',
  ]);
  // O(1) bypass check — checks exact host then walks up parent domains once
  function _isBypassHost(host) {
    if (_cspBypassSet.has(host)) return true;
    const dot = host.indexOf('.');
    if (dot !== -1) return _cspBypassSet.has(host.slice(dot + 1));
    return false;
  }
  // Block-result cache — avoids re-running shouldBlock() for the same URL
  const _blockCache = new Map();
  const _BLOCK_CACHE_MAX = 800;
  function _shouldBlockCached(url, adblockEnabled, level, isMainFrame = false) {
    if (!adblockEnabled) return false;
    // Never block main-frame navigations using downloaded filter lists — those lists are
    // designed to block sub-resources (scripts, images, XHR), not entire pages. Applying
    // them to page navigations causes legitimate sites (e.g. baidu.com) to be blocked
    // because ad-network rules in EasyList match their root domain.
    const domains = isMainFrame ? null : _filterDomains;
    const key = (isMainFrame ? 'mf:' : '') + url.slice(0, 160);
    if (_blockCache.has(key)) return _blockCache.get(key);
    const result = shouldBlock(url, adblockEnabled, level, domains);
    if (_blockCache.size >= _BLOCK_CACHE_MAX) {
      _blockCache.delete(_blockCache.keys().next().value);
    }
    _blockCache.set(key, result);
    return result;
  }
  ses.webRequest.onHeadersReceived({ urls: ['*://*/*'] }, (details, cb) => {
    const h = {};
    try {
      const host = new URL(details.url).hostname.toLowerCase().replace(/^www\./, '');
      const isBypass = _isBypassHost(host);
      for (const [k, v] of Object.entries(details.responseHeaders || {})) {
        const lk = k.toLowerCase();
        // Always strip COOP/COEP from every site — in a single-user browser these
        // headers serve no purpose and actively BREAK OAuth flows: when a Google/GitHub
        // login popup navigates to the callback URL on the original site, that site's
        // COOP:same-origin header severs window.opener so the parent page never gets
        // the auth code, permanently breaking Sign-in-with-Google/GitHub etc.
        if (lk === 'cross-origin-opener-policy' ||
            lk === 'cross-origin-embedder-policy') {
          continue;
        }
        // For auth/bypass domains also strip CSP, X-Frame-Options, Permissions-Policy,
        // and CORP so our preload spoofing injection works and login forms can submit.
        if (isBypass && (
            lk === 'content-security-policy' ||
            lk === 'content-security-policy-report-only' ||
            lk === 'x-frame-options' ||
            lk === 'permissions-policy' ||
            lk === 'cross-origin-resource-policy')) {
          continue;
        }
        // Enforce SameSite=Lax on Set-Cookie headers that lack a SameSite directive.
        // This prevents third-party cookies from being sent cross-site, blocking the
        // classic cookie-sync / cross-site profiling attack at the protocol level.
        if (lk === 'set-cookie') {
          h[k] = v.map(cookie => {
            const lower = cookie.toLowerCase();
            // Don't touch cookies that already declare SameSite (respect site intent)
            if (lower.includes('samesite=')) return cookie;
            // Don't add SameSite to Secure cookies from the same auth bypass domains —
            // auth session cookies need SameSite=None for cross-origin login flows.
            if (isBypass && lower.includes('secure')) return cookie;
            return cookie + '; SameSite=Lax';
          });
          continue;
        }

        h[k] = v;
      }
    } catch {
      return cb({});
    }
    cb({ responseHeaders: h });
  });

  // Deny tracking-risk permissions; allow safe ones.
  // NOTE: 'notifications' is deliberately NOT denied — Google's login detection
  // checks Notification.permission at the native level, and 'denied' is a strong
  // signal that this is an embedded webview, not a real browser. Notifications
  // are still blocked visually (our JS stubs return 'default'/'prompt').
  const _deniedPerms = new Set(['geolocation', 'sensors', 'background-sync', 'payment-handler', 'idle-detection', 'periodic-background-sync', 'nfc', 'bluetooth', 'camera', 'microphone', 'midi', 'publickey-credentials-create', 'publickey-credentials-get']);
  ses.setPermissionRequestHandler((_, permission, callback) => {
    // When geo spoofing is enabled, allow geolocation — our JS serves fake coords
    if (permission === 'geolocation' && settings.geoEnabled) { callback(true); return; }
    callback(!_deniedPerms.has(permission));
  });
  ses.setPermissionCheckHandler((_, permission) => {
    if (permission === 'geolocation' && settings.geoEnabled) return true;
    return !_deniedPerms.has(permission);
  });
  // Block navigation to dangerous schemes
  ses.on('will-navigate', (event, url) => {
    if (/^(javascript|vbscript|file):/i.test(url)) event.preventDefault();
  });
  ses.on('will-redirect', (event, url) => {
    if (/^(javascript|vbscript|file):/i.test(url)) event.preventDefault();
  });

  ses.on('will-download', (_, item) => {
    // Set custom download folder if configured
    if (settings.downloadPath) {
      try {
        const saveTo = path.join(settings.downloadPath, item.getFilename());
        item.setSavePath(saveTo);
      } catch {}
    }
    const entry = {
      id: Date.now(), filename: item.getFilename(),
      path: '', size: item.getTotalBytes(), received: 0, state: 'progressing',
      speed: 0, startTime: Date.now(), paused: false,
    };
    let _lastBytes = 0, _lastTime = Date.now();
    downloads.unshift(entry);
    _downloadItems.set(entry.id, item);
    send('downloads:update', downloads);

    item.on('updated', (__, state) => {
      const now   = Date.now();
      const bytes = item.getReceivedBytes();
      const dt    = (now - _lastTime) / 1000;
      entry.speed   = dt > 0.1 ? Math.round((bytes - _lastBytes) / dt) : entry.speed;
      _lastBytes = bytes; _lastTime = now;
      entry.state    = state;
      entry.paused   = item.isPaused();
      entry.received = bytes;
      entry.path     = item.getSavePath() || entry.path;
      send('downloads:update', downloads);
    });
    item.once('done', (__, state) => {
      entry.state    = state;
      entry.speed    = 0;
      entry.paused   = false;
      entry.received = item.getReceivedBytes();
      entry.path     = item.getSavePath() || entry.path;
      _downloadItems.delete(entry.id);
      save(F.downloads, downloads.filter(d => d.state !== 'progressing'));
      send('downloads:update', downloads);
    });
  });
}

// ── App ready ─────────────────────────────────────────────────────────────────
app.whenReady().then(() => {
  initStorage();   // app.getPath() now works
  // Load filter lists from local cache (or download if not cached / stale).
  // Runs async in background — blocking never impacts app startup.
  _loadFilterLists(false).catch(() => {});
  CHROME_H = settings.compactMode ? 72 : 82;  // sync with CSS --chrome-h on startup
  verticalTabsOn = !!settings.verticalTabs;
  // Register as default browser in Windows Default Apps (writes Registry Capabilities)
  if (process.platform === 'win32') _registerWindowsDefaultBrowser();

  // On macOS: use titleBarStyle:'hidden' + trafficLightPosition so native traffic
  // lights appear inside the tab row (matching the 78px mac-spacer).
  // On Windows/Linux: fully frameless (custom window controls in HTML).
  const _macWinOpts = process.platform === 'darwin' ? {
    titleBarStyle: 'hidden',
    trafficLightPosition: { x: 12, y: 10 }, // y=10 vertically centers in the 34px tab row
  } : {
    frame: false,
  };

  // Linux: transparency requires a compositor (picom, mutter, etc.). Without one,
  // the window renders with a solid black background. Use a solid colour on Linux
  // to guarantee correct rendering regardless of compositor availability.
  const _isLinux = process.platform === 'linux';

  win = new BrowserWindow({
    width: 1280, height: 820,
    minWidth: 640, minHeight: 400,
    ..._macWinOpts,
    transparent: !_isLinux,
    backgroundColor: _isLinux ? '#06060f' : '#00000000',
    icon: path.join(__dirname, 'assets',
      process.platform === 'darwin' ? 'logo.icns' :
      process.platform === 'linux'  ? 'logo.png'  : 'logo.ico'),
    webPreferences: {
      nodeIntegration:  true,
      contextIsolation: false,
      webviewTag:       true,
      autoplayPolicy:   'no-user-gesture-required',
    },
    show: false,
  });

  win.loadFile(path.join(__dirname, 'index.html'));

  win.once('ready-to-show', () => {
    setupSession(session.fromPartition('persist:main'));
    setupSession(session.fromPartition('incognito')); // set up blocking/UA for private tabs
    // Explicitly set the UA on defaultSession at the session level so the underlying
    // Chromium UA string (used by Fetch, XHR, service workers) is also spoofed.
    session.defaultSession.setUserAgent(SPOOF_UA);
    // Clear Google service workers — they run in a separate context where our JS
    // overrides don't apply, so they can report real Electron identity to Google.
    const mainSes = session.fromPartition('persist:main');
    ['https://accounts.google.com','https://www.google.com','https://myaccount.google.com',
     'https://mail.google.com','https://www.youtube.com','https://play.google.com'].forEach(origin => {
      mainSes.clearStorageData({ storages: ['serviceworkers'], origin }).catch(() => {});
    });
    // Belt-and-suspenders: apply the FULL CH-UA header set to defaultSession so every
    // request (service workers, preflight, non-partitioned oauth) looks like Chrome.
    session.defaultSession.webRequest.onBeforeSendHeaders({ urls: ['*://*/*'] }, (details, cb) => {
      const h = { ...details.requestHeaders };
      h['User-Agent']                  = SPOOF_UA;
      h['Sec-CH-UA']                   = SPOOF_UA_HINTS;
      h['Sec-CH-UA-Mobile']            = '?0';
      h['Sec-CH-UA-Platform']          = '"Windows"';
      h['Sec-CH-UA-Platform-Version']  = '"10.0.0"';
      h['Sec-CH-UA-Arch']              = '"x86"';
      h['Sec-CH-UA-Bitness']           = '"64"';
      h['Sec-CH-UA-Full-Version']      = '"135.0.7049.85"';
      h['Sec-CH-UA-Full-Version-List'] = '"Not_A Brand";v="8.0.0.0", "Chromium";v="135.0.7049.85", "Google Chrome";v="135.0.7049.85"';
      cb({ requestHeaders: h });
    });
    win.show();
    // Seed wobble position tracker so the FIRST drag immediately produces wobble
    // instead of just seeding the baseline (fixes the "no wobble on first drag" bug).
    try { const [wx, wy] = win.getPosition(); _wobblePX = wx; _wobblePY = wy; } catch {}
    // Load uBlock Origin (async — downloads on first run, then loads from cache)
    setupUBO().catch(e => console.error('[uBO] setup error:', e));
    // Restore previous session tabs if enabled
    const _savedSession = (settings.restoreSession && F.sessions) ? load(F.sessions, []) : [];
    if (_savedSession.length > 0) {
      // Load the first (active) tab immediately; stagger the rest so they don't
      // all compete for bandwidth/CPU at startup and slow down the first page.
      createTab(_savedSession[0], true);
      _savedSession.slice(1).forEach((url, i) => {
        setTimeout(() => { try { createTab(url, false); } catch {} }, (i + 1) * 600);
      });
    } else {
      createTab('newtab', true);
    }
    // Open URL passed on command line (RAW launched as default browser / open-with handler)
    const _startUrl = getArgUrl(process.argv);
    if (_startUrl) createTab(_startUrl, true);
    if (_pendingExtUrl) { createTab(_pendingExtUrl, true); _pendingExtUrl = null; }
    initDiscordRPC();
    // Apply saved preferred language to all requests
    if (settings.preferredLanguage) applyPreferredLanguage(settings.preferredLanguage);
    // Send settings:loaded so index.html can initialize state that depends on
    // settings (e.g. vertical tabs). main.js only ever sends 'settings:set' on
    // changes, so the initial state was never delivered — vertical tabs broke.
    win.webContents.send('settings:loaded', settings);
    // Report yt-dlp local status at startup — no network call (user triggers explicit checks)
    setTimeout(() => {
      try {
        const bin = ytdlpBinPath();
        const binExists = fs.existsSync(bin);
        if (!binExists) {
          send('ytdlp:status', { ready: false, version: null, updateAvailable: false });
        } else {
          const local = ytdlpReadLocalVersion();
          send('ytdlp:status', { ready: true, version: local || 'unknown', updateAvailable: false });
        }
      } catch {}
    }, 1000);
    // Auto-download Widevine CDM if not already loaded (no Chrome/Edge needed)
    // Runs 5 s after startup to avoid competing with initial page loads.
    // Load Widevine asynchronously without blocking startup
    setTimeout(() => { 
      widevineAutoDownload().catch(e => {
        console.log('Widevine auto-download failed:', e);
      });
    }, 500);
    // Lightweight anonymous usage/perf snapshot (if enabled)
    setTimeout(() => {
      sendTelemetry('usage', { event: 'app_start' });
      sendTelemetry('perf',  { event: 'baseline' });
    }, 8000);
    // Keep the cached page snapshot reasonably fresh for panel popups.
    // 15 s interval — on-load snapshots (did-stop-loading) cover the common case;
    // this interval only matters for live-updating pages (news tickers, etc.).
    _snapInterval = setInterval(() => {
      const tab = tabMap.get(activeId);
      if (!tab?.bv || panelOpen || tab.url === 'newtab' || tab.bv.webContents.isDestroyed()) return;
      tab.bv.webContents.capturePage().then(img => {
        tab.snapshot = 'data:image/jpeg;base64,' + img.toJPEG(60).toString('base64');
      }).catch(() => {});
    }, 15000);
    // Start memory saver and metrics collection
    _startMemSaver();
    _startMemMetrics();

    // Auto-show default browser prompt if not default and user hasn't dismissed
    setTimeout(() => {
      try {
        if (settings.defaultBrowserPromptDismissed) return;
        if (app.isDefaultProtocolClient('https')) return;
        const { BrowserWindow: BW } = require('electron');
        const promptWin = new BW({
          width: 400, height: 310, resizable: false,
          frame: false, transparent: true, alwaysOnTop: true,
          show: false, parent: win, modal: false,
          webPreferences: { nodeIntegration: true, contextIsolation: false }
        });
        promptWin.loadFile(path.join(__dirname, 'assets', 'default-browser-prompt.html'));
        promptWin.once('ready-to-show', () => {
          promptWin.center();
          promptWin.show();
          _sendThemeToPopup(promptWin);
        });
      } catch {}
    }, 4000);
  });

  win.on('resize', () => {
    if (panelOpen) return;
    for (const t of tabMap.values()) {
      if (t.bv && t.url !== 'newtab' && !t.bv.webContents.isDestroyed()) {
        try { setBounds(t.bv); } catch {}
      }
    }
  });

  win.on('maximize',   () => send('win:state', 'maximized'));
  win.on('unmaximize', () => send('win:state', 'normal'));
  win.on('close', (e) => {
    // First-time close confirmation dialog — only when there are real browsing tabs
    if (!settings.closeConfirmSkip && !settings._closingNow) {
      const hasRealTabs = [...tabMap.values()].some(t => t.url && t.url !== 'newtab');
      if (hasRealTabs) {
        e.preventDefault();
        // Show close-confirm popup as overlay — do NOT park the BV.
        // The popup is a transparent, always-on-top window that sits above the
        // main window, so the website stays visible behind the semi-transparent
        // backdrop. Parking the BV would blank the content area.
        _showCloseConfirmPopup();
        return;
      }
    }
    settings._closingNow = false; // reset one-shot bypass flag
    if (_closeConfirmWin && !_closeConfirmWin.isDestroyed()) {
      try { _closeConfirmWin.close(); } catch {}
    }
    if (_sidebarAddWin && !_sidebarAddWin.isDestroyed()) {
      try { _sidebarAddWin.close(); } catch {}
    }
    if (incognitoWin && !incognitoWin.isDestroyed()) {
      try { incognitoWin.close(); } catch {}
    }
    if (uboPopupWin && !uboPopupWin.isDestroyed()) {
      try { uboPopupWin.close(); } catch {}
    }
    if (_browserSwitchWin && !_browserSwitchWin.isDestroyed()) {
      try { _browserSwitchWin.close(); } catch {}
      _browserSwitchWin = null;
    }
    // Close all panel popups
    Object.values(_panelPopups).forEach(e => {
      if (e.win && !e.win.isDestroyed()) { try { e.win.close(); } catch {} }
    });
  });

  // Hide all popups when main window minimizes, restore when it comes back
  win.on('minimize', () => {
    if (uboPopupWin && !uboPopupWin.isDestroyed()) try { uboPopupWin.hide(); } catch {}
    if (_browserSwitchWin && !_browserSwitchWin.isDestroyed()) try { _browserSwitchWin.hide(); } catch {}
    Object.values(_panelPopups).forEach(e => {
      if (e.win && !e.win.isDestroyed()) try { e.win.hide(); } catch {}
    });
  });
  win.on('restore', () => {
    if (uboPopupWin && !uboPopupWin.isDestroyed()) try { uboPopupWin.show(); } catch {}
    if (_browserSwitchWin && !_browserSwitchWin.isDestroyed()) try { _browserSwitchWin.show(); } catch {}
    Object.values(_panelPopups).forEach(e => {
      if (e.win && !e.win.isDestroyed()) try { e.win.show(); } catch {}
    });
  });
  win.on('hide', () => {
    if (uboPopupWin && !uboPopupWin.isDestroyed()) try { uboPopupWin.hide(); } catch {}
    if (_browserSwitchWin && !_browserSwitchWin.isDestroyed()) try { _browserSwitchWin.hide(); } catch {}
    Object.values(_panelPopups).forEach(e => {
      if (e.win && !e.win.isDestroyed()) try { e.win.hide(); } catch {}
    });
  });
  win.on('show', () => {
    if (uboPopupWin && !uboPopupWin.isDestroyed()) try { uboPopupWin.show(); } catch {}
    if (_browserSwitchWin && !_browserSwitchWin.isDestroyed()) try { _browserSwitchWin.show(); } catch {}
    Object.values(_panelPopups).forEach(e => {
      if (e.win && !e.win.isDestroyed()) try { e.win.show(); } catch {}
    });
  });
  win.on('closed',     () => { win = null; });

  // Wobble window effect — track position delta on move + post-drag oscillation
  let _wobblePX = null, _wobblePY = null; // null until first move
  let _wobbleLastDX = 0, _wobbleLastDY = 0;
  let _wobbleMoveTimer = null;
  let _wobbleOscTimer  = null;
  // _isOscillating is declared at module scope (near ubo variables)

  /* After the drag ends, oscillate the OS window position so ALL content
   * (including BrowserViews) visibly bounces — true Compiz floppy feel. */
  function _startWobbleOscillation(initVX, initVY) {
    if (_wobbleOscTimer) { clearTimeout(_wobbleOscTimer); _wobbleOscTimer = null; }
    if (!settings.wobbleEffect || !win || win.isDestroyed()) return;
    try {
      const [targetX, targetY] = win.getPosition();
      let px = targetX, py = targetY;
      // Preserve most of the drag velocity so the initial bounce is satisfying
      let vx = initVX * 0.95, vy = initVY * 0.95;
      const K = 0.055, DAMP = 0.78;
      let frame = 0;
      // Calculate uboPopupWin offset relative to main window so popup follows
      let uboOffX = 0, uboOffY = 0;
      if (uboPopupWin && !uboPopupWin.isDestroyed()) {
        try {
          const [ux, uy] = uboPopupWin.getPosition();
          uboOffX = ux - targetX; uboOffY = uy - targetY;
        } catch {}
      }
      // Calculate all panel popup offsets so they follow during wobble
      const _panelOffsets = {};
      Object.entries(_panelPopups).forEach(([name, e]) => {
        if (e.win && !e.win.isDestroyed()) {
          try {
            const [px2, py2] = e.win.getPosition();
            _panelOffsets[name] = { x: px2 - targetX, y: py2 - targetY };
          } catch {}
        }
      });
      _isOscillating = true;
      send('win:wobble-start');
      let prevRX = targetX, prevRY = targetY;
      function step() {
        if (!win || win.isDestroyed() || !settings.wobbleEffect) {
          _isOscillating = false; send('win:wobble-end'); return;
        }
        vx = (vx - K * (px - targetX)) * DAMP;
        vy = (vy - K * (py - targetY)) * DAMP;
        px += vx; py += vy;
        frame++;
        if (frame > 400 ||
            (Math.abs(vx) < 0.12 && Math.abs(vy) < 0.12 &&
             Math.abs(px - targetX) < 0.15 && Math.abs(py - targetY) < 0.15)) {
          try { win.setPosition(targetX, targetY); } catch {}
          if (uboPopupWin && !uboPopupWin.isDestroyed())
            try { uboPopupWin.setPosition(targetX + uboOffX, targetY + uboOffY); } catch {}
          Object.entries(_panelOffsets).forEach(([name, off]) => {
            const e = _panelPopups[name];
            if (e?.win && !e.win.isDestroyed())
              try { e.win.setPosition(targetX + off.x, targetY + off.y); } catch {}
          });
          // Sync tracker so the first user-drag after oscillation has a correct baseline
          _wobblePX = targetX; _wobblePY = targetY;
          _isOscillating = false;
          send('win:wobble-end');
          return;
        }
        const rx = Math.round(px), ry = Math.round(py);
        try { win.setPosition(rx, ry); } catch {}
        if (uboPopupWin && !uboPopupWin.isDestroyed())
          try { uboPopupWin.setPosition(rx + uboOffX, ry + uboOffY); } catch {}
        Object.entries(_panelOffsets).forEach(([name, off]) => {
          const e = _panelPopups[name];
          if (e?.win && !e.win.isDestroyed())
            try { e.win.setPosition(rx + off.x, ry + off.y); } catch {}
        });
        // Drive the CSS spring mesh on #chrome in sync with the window bounce
        const ddx = rx - prevRX, ddy = ry - prevRY;
        if (Math.abs(ddx) > 0.1 || Math.abs(ddy) > 0.1) send('win:wobble-move', { dx: ddx, dy: ddy });
        prevRX = rx; prevRY = ry;
        _wobbleOscTimer = setTimeout(step, 16); // ~60 fps
      }
      step();
    } catch { _isOscillating = false; send('win:wobble-end'); }
  }

  win.on('move', () => {
    // Keep uboPopupWin pinned relative to the main window on every move
    if (!_isOscillating && uboPopupWin && !uboPopupWin.isDestroyed() && _uboRelOffset) {
      try {
        const [wx, wy] = win.getPosition();
        uboPopupWin.setPosition(Math.round(wx + _uboRelOffset.x), Math.round(wy + _uboRelOffset.y));
      } catch {}
    }
    // Keep browser-switch popup pinned relative to the main window on every move
    if (!_isOscillating && _browserSwitchWin && !_browserSwitchWin.isDestroyed() && _browserSwitchRelOffset) {
      try {
        const [wx, wy] = win.getPosition();
        _browserSwitchWin.setPosition(Math.round(wx + _browserSwitchRelOffset.x), Math.round(wy + _browserSwitchRelOffset.y));
      } catch {}
    }
    // Keep all panel popups pinned relative to the main window on every move
    if (!_isOscillating) {
      Object.values(_panelPopups).forEach(e => {
        if (e.win && !e.win.isDestroyed() && e.relOffset) {
          try {
            const [wx, wy] = win.getPosition();
            e.win.setPosition(Math.round(wx + e.relOffset.x), Math.round(wy + e.relOffset.y));
          } catch {}
        }
      });
    }
    if (!settings.wobbleEffect) return;
    // During setPosition-based oscillation, ignore synthesised move events —
    // they would cause double-wobble (CSS + OS) and re-arm the oscillation timer.
    if (_isOscillating) return;
    if (!win || win.isDestroyed()) return;
    const [x, y] = win.getPosition();
    if (_wobblePX === null) { _wobblePX = x; _wobblePY = y; return; } // seed position
    const dx = x - _wobblePX, dy = y - _wobblePY;
    _wobblePX = x; _wobblePY = y;
    if (Math.abs(dx) > 0.4 || Math.abs(dy) > 0.4) {
      _wobbleLastDX = dx; _wobbleLastDY = dy;
      send('win:wobble-move', { dx, dy });
      // Detect drag-end: if no more move events for 70 ms → drag released
      clearTimeout(_wobbleMoveTimer);
      _wobbleMoveTimer = setTimeout(() => {
        _startWobbleOscillation(_wobbleLastDX, _wobbleLastDY);
      }, 70);
    }
  });

app.on('before-quit', () => {
  if (typeof _snapInterval !== 'undefined') clearInterval(_snapInterval);
  if (typeof _memSaverInterval !== 'undefined' && _memSaverInterval) clearInterval(_memSaverInterval);
  if (typeof _memMetricsInterval !== 'undefined' && _memMetricsInterval) clearInterval(_memMetricsInterval);
  // Save open tabs for session restore (only non-newtab, non-view-source tabs)
  if (settings.restoreSession && F.sessions) {
    const sessionUrls = [...tabMap.values()]
      .filter(t => t.url && t.url !== 'newtab' && !t.url.startsWith('view-source:'))
      .map(t => t.url);
    save(F.sessions, sessionUrls);
  } else if (F.sessions) {
    // Clear saved session if restore is disabled
    save(F.sessions, []);
  }
  if (_rpcInterval) { clearInterval(_rpcInterval); _rpcInterval = null; }
  if (_bugCursorInterval) { clearInterval(_bugCursorInterval); _bugCursorInterval = null; }
  if (discordRpc) { try { discordRpc.destroy(); } catch {} }
});

  // Context menu for editable fields in the main window (omnibox, newtab search, etc.)
  win.webContents.on('context-menu', (_, p) => {
    if (!p.isEditable) return;
    Menu.buildFromTemplate([
      { label: 'Emojis', click: () => app.showEmojiPanel() },
      { type: 'separator' },
      { label: 'Cut',   role: 'cut',   enabled: p.editFlags.canCut   },
      { label: 'Copy',  role: 'copy',  enabled: p.editFlags.canCopy  },
      { label: 'Paste', role: 'paste', enabled: p.editFlags.canPaste },
      { type: 'separator' },
      { label: 'Undo',                 role: 'undo',             enabled: p.editFlags.canUndo     },
      { label: 'Redo',                 role: 'redo',             enabled: p.editFlags.canRedo     },
      { type: 'separator' },
      { label: 'Select All',           role: 'selectAll',        enabled: p.editFlags.canSelectAll },
      { type: 'separator' },
      { label: 'Copy to Clipboard',    click: () => { clipboard.writeText(p.selectionText || ''); }, enabled: !!p.selectionText },
    ]).popup({ window: win });
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
    // Force-exit if discord-rpc or other async handles keep the event loop alive
    setTimeout(() => process.exit(0), 1500).unref();
  }
});

// ── IPC: Init ─────────────────────────────────────────────────────────────────
ipcMain.handle('init', () => ({
  tabs:         [...tabMap.values()].map(tabData),
  bookmarks,
  history:      history.slice(0, 300),
  settings,
  downloads,
  groups:       [...groupMap.values()],
  platform:     process.platform,
  userWhitelist,
  blockedTotal: totalBlocked,
}));

// ── IPC: Bug Cursor (tracks cursor over BrowserView content) ─────────────────
let _bugCursorInterval = null;
ipcMain.on('bug-cursor:start', () => {
  if (_bugCursorInterval) return;
  _bugCursorInterval = setInterval(() => {
    if (!win || win.isDestroyed()) return;
    const pt = screen.getCursorScreenPoint();
    const [wx, wy] = win.getPosition();
    win.webContents.send('bug-cursor:pos', pt.x - wx, pt.y - wy);
  }, 16);
});
ipcMain.on('bug-cursor:stop', () => {
  if (_bugCursorInterval) { clearInterval(_bugCursorInterval); _bugCursorInterval = null; }
});

// ── IPC: Window controls ──────────────────────────────────────────────────────
ipcMain.on('win:minimize', () => win?.minimize());
ipcMain.on('win:maximize', () => win?.isMaximized() ? win.unmaximize() : win?.maximize());
ipcMain.on('win:close',    () => win?.close());
ipcMain.on('win:close-confirmed', (_, { remember }) => {
  if (remember) {
    settings.closeConfirmSkip = true;
    save(F.settings, settings);
  } else {
    settings._closingNow = true; // one-shot bypass so close event runs cleanup
  }
  if (win && !win.isDestroyed()) win.close();
});
ipcMain.on('win:close-cancelled', () => {
  // Re-attach BV that was removed before showing close dialog
  const _ct = tabMap.get(activeId);
  if (_ct?.bv && _ct.url !== 'newtab' && !_ct.bv.webContents.isDestroyed()) {
    try { win.addBrowserView(_ct.bv); setBounds(_ct.bv); } catch {}
  }
});
ipcMain.on('calm-mode:set', (_, enabled) => { if (win) win.setOpacity(enabled ? 0.88 : 1.0); });

// ── Close confirm popup ───────────────────────────────────────────────────────
function _showCloseConfirmPopup() {
  if (_closeConfirmWin && !_closeConfirmWin.isDestroyed()) { _closeConfirmWin.focus(); return; }

  const [wx, wy] = win.getPosition();
  const [ww, wh] = win.getSize();

  _closeConfirmWin = new BrowserWindow({
    parent: win,
    x: wx, y: wy, width: ww, height: wh,
    frame: false, resizable: false, show: false,
    skipTaskbar: true, alwaysOnTop: true,
    transparent: true, backgroundColor: '#00000000', hasShadow: false,
    webPreferences: { nodeIntegration: true, contextIsolation: false },
  });

  _closeConfirmWin.loadFile(path.join(__dirname, 'assets', 'close-confirm-popup.html'));

  _closeConfirmWin.webContents.on('did-finish-load', () => {
    if (!_closeConfirmWin || _closeConfirmWin.isDestroyed()) return;
    _sendThemeToPopup(_closeConfirmWin);
    const restoreSession = !!(settings && settings.restoreSession);
    _closeConfirmWin.webContents.send('cc:init', { restoreSession });
    _closeConfirmWin.show();
  });

  _closeConfirmWin.on('closed', () => { _closeConfirmWin = null; });
}

ipcMain.on('cc:yes', (_, { remember }) => {
  if (_closeConfirmWin && !_closeConfirmWin.isDestroyed()) {
    try { _closeConfirmWin.close(); } catch {}
  }
  if (remember) {
    settings.closeConfirmSkip = true;
    save(F.settings, settings);
  }
  // Trigger the renderer wobble-close flow
  send('win:do-close');
});

ipcMain.on('cc:no', () => {
  if (_closeConfirmWin && !_closeConfirmWin.isDestroyed()) {
    try { _closeConfirmWin.close(); } catch {}
  }
});

// ── yt-dlp warning popup ──────────────────────────────────────────────────────
let _ytdlpWarnWin = null;

ipcMain.on('ytdlp-warn:show', (_, data) => {
  if (_ytdlpWarnWin && !_ytdlpWarnWin.isDestroyed()) { _ytdlpWarnWin.focus(); return; }
  if (!win || win.isDestroyed()) return;

  const [wx, wy] = win.getPosition();
  const [ww, wh] = win.getSize();

  _ytdlpWarnWin = new BrowserWindow({
    x: wx, y: wy, width: ww, height: wh,
    frame: false, resizable: false, show: false,
    skipTaskbar: true, alwaysOnTop: true,
    transparent: true, backgroundColor: '#00000000', hasShadow: false,
    webPreferences: { nodeIntegration: true, contextIsolation: false },
  });

  _ytdlpWarnWin.loadFile(path.join(__dirname, 'assets', 'ytdlp-warn-popup.html'));

  _ytdlpWarnWin.webContents.on('did-finish-load', () => {
    if (!_ytdlpWarnWin || _ytdlpWarnWin.isDestroyed()) return;
    _sendThemeToPopup(_ytdlpWarnWin);
    _ytdlpWarnWin.show();
  });

  _ytdlpWarnWin.on('closed', () => { _ytdlpWarnWin = null; });
});

ipcMain.on('ytdlp-warn:accept', () => {
  if (_ytdlpWarnWin && !_ytdlpWarnWin.isDestroyed()) {
    try { _ytdlpWarnWin.close(); } catch {}
  }
  send('ytdlp-warn:accepted');
});

ipcMain.on('ytdlp-warn:cancel', () => {
  if (_ytdlpWarnWin && !_ytdlpWarnWin.isDestroyed()) {
    try { _ytdlpWarnWin.close(); } catch {}
  }
});

// ── IPC: Tabs ─────────────────────────────────────────────────────────────────
ipcMain.on('tab:new', (_, url) => {
  // Strip dangerous schemes before creating tab — protects against crafted IPC calls
  const safe = (url && /^(javascript|vbscript|data|file):/i.test(url))
    ? (settings.searchEngine || 'https://duckduckgo.com/?q=') + encodeURIComponent(url)
    : (url || 'newtab');
  createTab(safe);
});
ipcMain.on('tab:switch',    (_, id)  => activateTab(id));
// ── Native tab context menu — renders above BrowserViews, no BV parking needed ──
ipcMain.on('tab:ctx', (_, { tabId }) => {
  const t = tabMap.get(tabId);
  if (!t) return;

  // Build group submenu
  const existingGroups = [...groupMap.values()];
  const groupSubmenu = [
    {
      label: 'New Group',
      click: () => {
        _nextGroupId++;
        const gid = 'g-' + _nextGroupId;
        const autoName = _domainLabel(t.url) || 'Group ' + _nextGroupId;
        groupMap.set(gid, { id: gid, name: autoName, color: GROUP_COLORS[(groupMap.size) % GROUP_COLORS.length], collapsed: false });
        t.groupId = gid;
        send('tab:update', tabData(t));
        send('tabs:reorder', [...tabMap.values()].map(tabData));
        sendGroupsUpdate();
      },
    },
    ...(existingGroups.length ? [{ type: 'separator' }] : []),
    ...existingGroups.map(g => ({
      label: `Add to "${g.name}"`,
      click: () => {
        t.groupId = g.id;
        send('tab:update', tabData(t));
        send('tabs:reorder', [...tabMap.values()].map(tabData));
        sendGroupsUpdate();
      },
    })),
  ];
  if (t.groupId) {
    groupSubmenu.push({ type: 'separator' });
    groupSubmenu.push({
      label: 'Remove from Group',
      click: () => {
        t.groupId = null;
        send('tab:update', tabData(t));
        send('tabs:reorder', [...tabMap.values()].map(tabData));
        sendGroupsUpdate();
      },
    });
  }

  Menu.buildFromTemplate([
    { label: t.pinned ? 'Unpin Tab' : 'Pin Tab', click: () => { t.pinned = !t.pinned; send('tab:update', tabData(t)); send('tabs:reorder', [...tabMap.values()].map(tabData)); } },
    { label: t.muted ? 'Unmute Tab' : 'Mute Tab', click: () => { ipcMain.emit('tab:mute', null, tabId); } },
    { type: 'separator' },
    { label: 'Tab Group', submenu: groupSubmenu },
    { label: 'Group Similar Tabs', click: () => {
      // Group all tabs sharing the same domain as this tab
      const host = _tabHost(t.url);
      if (!host) return;
      const domainTabs = [...tabMap.values()].filter(x => !x.pinned && _tabHost(x.url) === host);
      if (domainTabs.length < 2) return; // need at least 2 tabs to group
      // Find existing group for this domain or create new
      let grp = null;
      for (const dt of domainTabs) {
        if (dt.groupId) { grp = groupMap.get(dt.groupId); if (grp) break; }
      }
      if (!grp) {
        _nextGroupId++;
        const gid = 'g-' + _nextGroupId;
        grp = { id: gid, name: _domainLabel(t.url) || host, color: GROUP_COLORS[(groupMap.size) % GROUP_COLORS.length], collapsed: false };
        groupMap.set(gid, grp);
      }
      for (const dt of domainTabs) { dt.groupId = grp.id; send('tab:update', tabData(dt)); }
      send('tabs:reorder', [...tabMap.values()].map(tabData));
      sendGroupsUpdate();
    }},
    { label: 'Auto-Group All by Site', click: () => {
      // Group all non-pinned tabs by their domain
      const domainBuckets = new Map(); // host → [tab, ...]
      for (const tab of tabMap.values()) {
        if (tab.pinned || tab.url === 'newtab') continue;
        const host = _tabHost(tab.url);
        if (!host) continue;
        if (!domainBuckets.has(host)) domainBuckets.set(host, []);
        domainBuckets.get(host).push(tab);
      }
      for (const [host, tabs] of domainBuckets) {
        if (tabs.length < 2) continue;
        // Check if any tab already belongs to a group
        let grp = null;
        for (const tb of tabs) {
          if (tb.groupId) { grp = groupMap.get(tb.groupId); if (grp) break; }
        }
        if (!grp) {
          _nextGroupId++;
          const gid = 'g-' + _nextGroupId;
          grp = { id: gid, name: _domainLabel(tabs[0].url) || host, color: GROUP_COLORS[(groupMap.size) % GROUP_COLORS.length], collapsed: false };
          groupMap.set(gid, grp);
        }
        for (const tb of tabs) { tb.groupId = grp.id; send('tab:update', tabData(tb)); }
      }
      send('tabs:reorder', [...tabMap.values()].map(tabData));
      sendGroupsUpdate();
    }},
    { type: 'separator' },
    { label: 'Reload Tab',    click: () => { t.bv?.webContents.reload(); } },
    { label: 'Duplicate Tab', click: () => { createTab(t.url); } },
    { type: 'separator' },
    { label: 'Close Tab',          click: () => { closeTab(tabId); } },
    { label: 'Close Other Tabs',   click: () => { for (const id of [...tabMap.keys()]) if (id !== tabId) closeTab(id); } },
    { label: 'Close Tabs to Right', click: () => {
        const ids = [...tabMap.keys()];
        const idx = ids.indexOf(tabId);
        for (let i = idx + 1; i < ids.length; i++) closeTab(ids[i]);
      }
    },
  ]).popup({ window: win });
});

// ── Tab group IPC handlers ────────────────────────────────────────────────────
ipcMain.on('tab:group:rename', (_, { groupId, name }) => {
  const g = groupMap.get(groupId);
  if (g) { g.name = name || 'Group'; sendGroupsUpdate(); }
});
ipcMain.on('tab:group:color', (_, { groupId, color }) => {
  const g = groupMap.get(groupId);
  if (g) { g.color = color; sendGroupsUpdate(); }
});
ipcMain.on('tab:group:toggle', (_, groupId) => {
  const g = groupMap.get(groupId);
  if (g) { g.collapsed = !g.collapsed; sendGroupsUpdate(); }
});
ipcMain.on('tab:group:delete', (_, groupId) => {
  groupMap.delete(groupId);
  for (const tab of tabMap.values()) {
    if (tab.groupId === groupId) { tab.groupId = null; send('tab:update', tabData(tab)); }
  }
  sendGroupsUpdate();
});
ipcMain.on('tab:group:ctx', (_, { groupId }) => {
  const g = groupMap.get(groupId);
  if (!g || !win) return;
  const colorItems = GROUP_COLORS.map(c => ({
    label: c.charAt(0).toUpperCase() + c.slice(1),
    type: 'checkbox',
    checked: g.color === c,
    click: () => { g.color = c; sendGroupsUpdate(); }
  }));
  const groupTabs = [...tabMap.values()].filter(t => t.groupId === groupId);
  const menu = Menu.buildFromTemplate([
    { label: `Group: ${g.name}`, enabled: false },
    { type: 'separator' },
    { label: 'Rename Group…', click: () => { send('group:prompt:rename', groupId); } },
    { label: 'Color', submenu: colorItems },
    { type: 'separator' },
    { label: g.collapsed ? 'Expand Group' : 'Collapse Group', click: () => { g.collapsed = !g.collapsed; sendGroupsUpdate(); } },
    { type: 'separator' },
    { label: `Close Group (${groupTabs.length} tabs)`, click: () => {
      for (const tab of groupTabs) closeTab(tab.id);
    }},
    { label: 'Ungroup All Tabs', click: () => {
      groupMap.delete(groupId);
      for (const tab of tabMap.values()) {
        if (tab.groupId === groupId) { tab.groupId = null; send('tab:update', tabData(tab)); }
      }
      sendGroupsUpdate();
    }}
  ]);
  menu.popup({ window: win });
});

ipcMain.on('tab:close',     (_, id)  => closeTab(id));
ipcMain.on('tab:duplicate', (_, id)  => { const t = tabMap.get(id); if (t) createTab(t.url); });
ipcMain.on('tab:pin',  (_, id) => {
  const t = tabMap.get(id);
  if (!t) return;
  t.pinned = !t.pinned;
  // Send full tab list so renderer can reorder pinned tabs to the left
  send('tab:update', tabData(t));
  send('tabs:reorder', [...tabMap.values()].map(tabData));
});
ipcMain.on('tab:mute', (_, id) => {
  const t = tabMap.get(id);
  if (!t) return;
  t.muted = !t.muted;
  t.bv?.webContents.setAudioMuted(t.muted);
  send('tab:update', tabData(t));
  if (id === activeId) send('nav:state', navData(t));
  send('audio:update', _getAudioTabs());
});
ipcMain.on('tab:skip', (_, { id, secs }) => {
  const t = tabMap.get(id);
  if (!t?.bv) return;
  const s = secs | 0;
  t.bv.webContents.executeJavaScript(
    `(function(){const v=document.querySelector('video');if(v)v.currentTime=Math.max(0,v.currentTime+${s});})()`,
  ).catch(() => {});
});
ipcMain.on('tab:playpause', (_, id) => {
  const t = tabMap.get(id);
  if (!t?.bv) return;
  t.bv.webContents.executeJavaScript(
    `(function(){const v=document.querySelector('video')||document.querySelector('audio');if(!v)return false;if(v.paused){v.play().catch(function(){});}else{v.pause();}return v.paused;})()`,
  ).then(paused => {
    t.paused = !!paused;
    send('audio:update', _getAudioTabs());
  }).catch(() => {});
});
ipcMain.on('tab:volume', (_, { id, volume }) => {
  const t = tabMap.get(id);
  if (!t?.bv) return;
  const vol = Math.max(0, Math.min(1, volume));
  t.volume = vol;
  t.bv.webContents.executeJavaScript(
    `(function(){document.querySelectorAll('video,audio').forEach(function(m){m.volume=${vol};});})()`,
  ).catch(() => {});
  send('audio:update', _getAudioTabs());
});
ipcMain.on('tab:seek', (_, { id, pct }) => {
  const t = tabMap.get(id);
  if (!t?.bv) return;
  const p = Math.max(0, Math.min(1, pct));
  t.bv.webContents.executeJavaScript(
    `(function(){const v=document.querySelector('video')||document.querySelector('audio');if(v&&isFinite(v.duration)&&v.duration>0)v.currentTime=v.duration*${p};})()`,
  ).catch(() => {});
});
ipcMain.handle('tab:get-time', async (_, id) => {
  const t = tabMap.get(id);
  if (!t?.bv || t.bv.webContents.isDestroyed()) return null;
  try {
    return await t.bv.webContents.executeJavaScript(
      `(function(){const v=document.querySelector('video')||document.querySelector('audio');return v?{ct:v.currentTime,dur:v.duration}:null;})()`,
    );
  } catch { return null; }
});

// ── IPC: Navigation ───────────────────────────────────────────────────────────
// Ensure BV is attached whenever the user actively navigates (safety net).
// NOTE: Does NOT guard against t.url==='newtab' — use attachBvForNav instead.
function ensureBvAttached(t) {
  if (!t?.bv || panelOpen) return;
  try { setBounds(t.bv); } catch {}
  try { win.addBrowserView(t.bv); } catch {}
}

// Force-attach BV for a navigation to a real URL.
// Handles the coming-from-newtab case: updates t.url eagerly so newtab-layer
// hides immediately in the renderer, then attaches the BV.
function attachBvForNav(t, url) {
  if (!t?.bv) return;
  const wasNewtab = t.url === 'newtab';
  t.url = url; // pre-set so newtab-layer hides + ensureBvAttached doesn't guard
  if (!panelOpen) {
    try { win.addBrowserView(t.bv); } catch {}
    setBounds(t.bv);
  }
  if (wasNewtab) {
    // Tell the renderer to hide newtab-layer immediately
    send('tab:update', tabData(t));
    if (t.id === activeId) send('nav:state', navData(t));
  }
}

// Force-load a URL in the active tab, bypassing the chrome:intercept guard
ipcMain.handle('nav:load-url', (_, url) => {
  const t = tabMap.get(activeId);
  if (!t) return;
  // Pre-approve the hostname so _guardNav won't re-intercept (e.g. chrome.com "Continue anyway").
  // Clears after 3 s to cover http→https redirects (two will-navigate events) automatically.
  try {
    const _bypassHost = new URL(url).hostname.replace(/^www\./, '').toLowerCase();
    _tempBypassSet.add(_bypassHost);
    setTimeout(() => _tempBypassSet.delete(_bypassHost), 3000);
  } catch {}
  if (t.url === 'newtab' || !t.bv || t.bv.webContents.isDestroyed()) {
    // Newtab — attach a BV and navigate (same path as nav:go for real pages)
    try { attachBvForNav(t, url); t.bv.webContents.loadURL(url); } catch {}
  } else {
    try { t.bv.webContents.loadURL(url); } catch {}
  }
});

ipcMain.on('nav:go', (_, { id, tabUrl }) => {
  const t = tabMap.get(id ?? activeId);
  if (!t) return;
  // Close any open panel before navigating — overlay must not block the new page
  if (panelOpen) {
    panelOpen  = false;
    panelClipX = 0;
    send('panels:closeAll');
  }
  // If the BV was parked for the omni dropdown, decrement the capturer count
  // immediately so it exits off-screen rendering mode before becoming visible
  // again. Without this, the BV is repositioned onscreen but stays in capturer
  // mode for ~160ms (until osCloseDrop fires), causing a compositor glitch that
  // makes the toolbar appear blurry/flickery at the top.
  if (_omniParked) {
    _omniParked = false;
    if (t.bv && !t.bv.webContents.isDestroyed()) {
      try { t.bv.webContents.decrementCapturerCount(); } catch {}
    }
  }
  const url = stripTracking(resolveUrl(tabUrl));
  if (url === 'newtab') {
    // Return to newtab: detach BV, update tab state
    try { win.removeBrowserView(t.bv); } catch {}
    t.url = 'newtab'; t.title = 'New Tab'; t.favicon = null;
    send('tab:update', tabData(t));
    if (id === activeId) {
      send('nav:state', navData(t));
      _rpcScreen = 'newtab'; updateDiscordRPC();
    }
  } else {
    attachBvForNav(t, url);
    t.bv.webContents.loadURL(url);
    if (id === activeId && !['settings', 'addons'].includes(_rpcScreen)) {
      _rpcScreen = 'website'; updateDiscordRPC();
    }
  }
});
ipcMain.on('nav:back', (_, id) => {
  if (panelOpen) { panelOpen = false; panelClipX = 0; send('panels:closeAll'); }
  const t = tabMap.get(id); ensureBvAttached(t); t?.bv.webContents.goBack();
});
ipcMain.on('nav:forward', (_, id) => {
  if (panelOpen) { panelOpen = false; panelClipX = 0; send('panels:closeAll'); }
  const t = tabMap.get(id); ensureBvAttached(t); t?.bv.webContents.goForward();
});
ipcMain.on('nav:reload', (_, id) => {
  if (panelOpen) { panelOpen = false; panelClipX = 0; send('panels:closeAll'); }
  const t = tabMap.get(id); if (t?.url === 'newtab') return; ensureBvAttached(t); t?.bv.webContents.reload();
});
ipcMain.on('nav:reload:hard', (_, id) => {
  if (panelOpen) { panelOpen = false; panelClipX = 0; send('panels:closeAll'); }
  const t = tabMap.get(id); if (t?.url === 'newtab') return; ensureBvAttached(t); t?.bv.webContents.reloadIgnoringCache();
});
ipcMain.on('nav:stop',        (_, id) => tabMap.get(id)?.bv.webContents.stop());
ipcMain.on('nav:home',        (_, id) => {
  const t = tabMap.get(id);
  if (!t) return;
  const hp = settings.homepage || 'newtab';
  if (hp === 'newtab') {
    try { win.removeBrowserView(t.bv); } catch {}
    t.url = 'newtab'; t.title = 'New Tab'; t.favicon = null;
    send('tab:update', tabData(t));
    if (id === activeId) send('nav:state', navData(t));
  } else {
    attachBvForNav(t, hp);
    t.bv.webContents.loadURL(hp);
  }
});

// ── Persistent media guard — injected once at page load ───────────────────────
// Wraps IntersectionObserver callbacks and HTMLVideoElement.pause so they check
// window._rbPanelOpen at *call time*. Because this runs at page load, the guards
// are in place before any panel ever opens — fixing the async timing race where
// _parkBV moved the BV offscreen before executeJavaScript could install overrides.
const PERSISTENT_MEDIA_GUARD_JS = `(function(){
  if (window._rbGuardInstalled) return;
  window._rbGuardInstalled = true;
  window._rbPanelOpen = window._rbPanelOpen || false;

  // Wrap IntersectionObserver: while panel is open, report every entry as fully
  // visible (ratio=1). YouTube's player calls .pause() inside its IO callback
  // when ratio drops to 0 — this prevents that entirely.
  if (window.IntersectionObserver) {
    var _OrigIO = window.IntersectionObserver;
    window.IntersectionObserver = function(cb, opts) {
      return new _OrigIO(function(entries, obs) {
        if (window._rbPanelOpen) {
          entries = entries.map(function(e) {
            var r = e.boundingClientRect;
            return {
              boundingClientRect: r,
              intersectionRatio:  1,
              intersectionRect:   r,
              isIntersecting:     true,
              isVisible:          true,
              contentRect:        r,
              rootBounds:         e.rootBounds,
              target:             e.target,
              time:               e.time
            };
          });
        }
        return cb(entries, obs);
      }, opts);
    };
    try { window.IntersectionObserver.prototype = _OrigIO.prototype; } catch(e) {}
  }

  // Wrap HTMLVideoElement.pause: silently drop automatic pauses while panel open.
  // Covers TikTok scroll-pause, YouTube miniplayer pause, etc.
  var _origPause = HTMLVideoElement.prototype.pause;
  HTMLVideoElement.prototype.pause = function() {
    if (window._rbPanelOpen) return;
    return _origPause.call(this);
  };

  // Wrap HTMLAudioElement.pause: same guard for audio-only players (Spotify, music).
  var _origAudioPause = HTMLAudioElement.prototype.pause;
  HTMLAudioElement.prototype.pause = function() {
    if (window._rbPanelOpen) return;
    return _origAudioPause.call(this);
  };

  // Suppress AbortError from interrupted play() calls that race with blocked pauses.
  var _origPlay = HTMLVideoElement.prototype.play;
  HTMLVideoElement.prototype.play = function() {
    var p = _origPlay.call(this);
    if (p && p.catch) p.catch(function() {});
    return p;
  };
  var _origAudioPlay = HTMLAudioElement.prototype.play;
  HTMLAudioElement.prototype.play = function() {
    var p = _origAudioPlay.call(this);
    if (p && p.catch) p.catch(function() {});
    return p;
  };

  // Block resize events while panel is open.
  // TikTok/YouTube/etc. re-read innerWidth/innerHeight on resize and rebuild their
  // virtual scroll lists — if the BV is parked at 2×2 they see a 2px viewport and
  // mark every video as off-screen. Blocking the event prevents that re-layout.
  window.addEventListener('resize', function(e) {
    if (window._rbPanelOpen) { e.stopImmediatePropagation(); }
  }, true);
})()`;

// ── Panel keep-alive: prevent videos/animations from pausing while BV is detached ──
// NOTE: PERSISTENT_MEDIA_GUARD_JS (injected at page load) handles IO/pause interception.
// This only needs to set the flag and suppress visibility/focus events.
const PANEL_KEEP_ALIVE_JS = `(function(){
  window._rbPanelOpen = true;

  // Guard video.pause() immediately — covers the case where PERSISTENT_MEDIA_GUARD_JS
  // was not yet injected (page still loading when user opens a panel).
  if (!HTMLVideoElement.prototype._rbPauseWrapped) {
    HTMLVideoElement.prototype._rbPauseWrapped = true;
    var _p0 = HTMLVideoElement.prototype.pause;
    HTMLVideoElement.prototype.pause = function () {
      if (window._rbPanelOpen) return;
      return _p0.call(this);
    };
  }
  // Guard audio.pause() — covers Spotify, music players, and any audio-only streams.
  if (!HTMLAudioElement.prototype._rbPauseWrapped) {
    HTMLAudioElement.prototype._rbPauseWrapped = true;
    var _a0 = HTMLAudioElement.prototype.pause;
    HTMLAudioElement.prototype.pause = function () {
      if (window._rbPanelOpen) return;
      return _a0.call(this);
    };
  }

  // Save real viewport dimensions BEFORE the BV is parked at 2x2.
  window._rbSavedW  = window.innerWidth;
  window._rbSavedH  = window.innerHeight;
  window._rbSavedCW = document.documentElement.clientWidth  || window._rbSavedW;
  window._rbSavedCH = document.documentElement.clientHeight || window._rbSavedH;

  function _def(obj, prop, val) {
    try { Object.defineProperty(obj, prop, { get: function(){ return val; }, configurable: true }); } catch(e) {}
  }

  // 1. innerWidth / innerHeight (YouTube, most players)
  _def(window, 'innerWidth',  window._rbSavedW);
  _def(window, 'innerHeight', window._rbSavedH);

  // 2. document.documentElement.clientWidth/clientHeight (TikTok virtual scroll)
  _def(document.documentElement, 'clientWidth',  window._rbSavedCW);
  _def(document.documentElement, 'clientHeight', window._rbSavedCH);

  // 3. visualViewport API (TikTok, Instagram Reels)
  if (window.visualViewport) {
    _def(window.visualViewport, 'width',      window._rbSavedW);
    _def(window.visualViewport, 'height',     window._rbSavedH);
    _def(window.visualViewport, 'scale',      1);
    _def(window.visualViewport, 'offsetTop',  0);
    _def(window.visualViewport, 'offsetLeft', 0);
  }

  // 4. Wrap ResizeObserver — callbacks fire with real 2x2 sizes and cause
  //    TikTok to unmount the current video and rebuild the scroll layout.
  //    Returning without calling the original callback prevents that reflow.
  if (window.ResizeObserver && !window._rbOrigRO) {
    window._rbOrigRO = window.ResizeObserver;
    function _PatchedRO(cb) {
      var _patched = function(entries, obs) {
        if (window._rbPanelOpen) return; // suppress while panel is open
        cb.call(this, entries, obs);
      };
      return new window._rbOrigRO(_patched);
    }
    _PatchedRO.prototype = window._rbOrigRO.prototype;
    window.ResizeObserver = _PatchedRO;
  }

  // 5. Block resize event so virtual scrollers don't recalculate grid layout.
  if (!window._rbResizeBlock) {
    window._rbResizeBlock = function(e) { e.stopImmediatePropagation(); };
    window.addEventListener('resize', window._rbResizeBlock, true);
  }

  // 6. Visibility / focus API
  _def(document, 'hidden',          false);
  _def(document, 'visibilityState', 'visible');
  if (!window._rbOrigHasFocus) {
    window._rbOrigHasFocus = document.hasFocus.bind(document);
    document.hasFocus = function() { return true; };
  }

  // 7. Block events that signal the page is going to the background.
  if (!window._rbVCBlock) {
    window._rbVCBlock = function(e) { e.stopImmediatePropagation(); };
    document.addEventListener('visibilitychange', window._rbVCBlock, true);
    window.addEventListener('blur',     window._rbVCBlock, true);
    window.addEventListener('pagehide', window._rbVCBlock, true);
    window.addEventListener('freeze',   window._rbVCBlock, true);
  }

  // 8. Suppress IntersectionObserver callbacks — belt-and-suspenders fix for
  //    any site that manually reads intersection ratios to decide whether to
  //    pause media (YouTube, Twitch, etc.). New observer instances get
  //    suppressed callbacks; existing observers are left intact because the
  //    BV is now parked at full height (no viewport dimension change at all).
  if (window.IntersectionObserver && !window._rbOrigIO) {
    window._rbOrigIO = window.IntersectionObserver;
    function _RbIO(cb, opts) {
      var _patched = function(entries, obs) {
        if (window._rbPanelOpen) return;
        cb.call(this, entries, obs);
      };
      return new window._rbOrigIO(_patched, opts);
    }
    _RbIO.prototype = window._rbOrigIO.prototype;
    window.IntersectionObserver = _RbIO;
  }
})()`;
const PANEL_RESTORE_ALIVE_JS = `(function(){
  window._rbPanelOpen = false;

  // 1. Restore innerWidth / innerHeight
  try { delete window.innerWidth;  } catch {}
  try { delete window.innerHeight; } catch {}
  delete window._rbSavedW; delete window._rbSavedH;

  // 2. Restore document.documentElement.clientWidth/clientHeight
  try { delete document.documentElement.clientWidth;  } catch {}
  try { delete document.documentElement.clientHeight; } catch {}
  delete window._rbSavedCW; delete window._rbSavedCH;

  // 3. Restore visualViewport
  if (window.visualViewport) {
    try { delete window.visualViewport.width;      } catch {}
    try { delete window.visualViewport.height;     } catch {}
    try { delete window.visualViewport.scale;      } catch {}
    try { delete window.visualViewport.offsetTop;  } catch {}
    try { delete window.visualViewport.offsetLeft; } catch {}
  }

  // 4. Restore ResizeObserver
  if (window._rbOrigRO) {
    window.ResizeObserver = window._rbOrigRO;
    delete window._rbOrigRO;
  }

  // 5. Remove resize blocker, then fire real resize so layouts rebuild.
  if (window._rbResizeBlock) {
    window.removeEventListener('resize', window._rbResizeBlock, true);
    delete window._rbResizeBlock;
  }
  setTimeout(function() {
    try { if (!window._rbPanelOpen) window.dispatchEvent(new Event('resize')); } catch {}
  }, 0);

  // 6. Restore visibility API
  try { delete document.hidden; } catch {}
  try { delete document.visibilityState; } catch {}

  // 7. Restore hasFocus
  if (window._rbOrigHasFocus) {
    document.hasFocus = window._rbOrigHasFocus;
    delete window._rbOrigHasFocus;
  }

  // 8. Remove event blockers
  if (window._rbVCBlock) {
    document.removeEventListener('visibilitychange', window._rbVCBlock, true);
    window.removeEventListener('blur',     window._rbVCBlock, true);
    window.removeEventListener('pagehide', window._rbVCBlock, true);
    window.removeEventListener('freeze',   window._rbVCBlock, true);
    delete window._rbVCBlock;
  }

  // 9. Restore IntersectionObserver
  if (window._rbOrigIO) {
    window.IntersectionObserver = window._rbOrigIO;
    delete window._rbOrigIO;
  }
})()`;

// ── Geolocation spoofing ───────────────────────────────────────────────────────
const GEO_REGIONS = {
  // North America
  'new-york':    { lat:  40.7128, lon:  -74.0060, label: 'New York',       flag: '🇺🇸', region: 'North America' },
  'los-angeles': { lat:  34.0522, lon: -118.2437, label: 'Los Angeles',    flag: '🇺🇸', region: 'North America' },
  'chicago':     { lat:  41.8781, lon:  -87.6298, label: 'Chicago',        flag: '🇺🇸', region: 'North America' },
  'miami':       { lat:  25.7617, lon:  -80.1918, label: 'Miami',          flag: '🇺🇸', region: 'North America' },
  'dallas':      { lat:  32.7767, lon:  -96.7970, label: 'Dallas',         flag: '🇺🇸', region: 'North America' },
  'seattle':     { lat:  47.6062, lon: -122.3321, label: 'Seattle',        flag: '🇺🇸', region: 'North America' },
  'atlanta':     { lat:  33.7490, lon:  -84.3880, label: 'Atlanta',        flag: '🇺🇸', region: 'North America' },
  'toronto':     { lat:  43.6511, lon:  -79.3832, label: 'Toronto',        flag: '🇨🇦', region: 'North America' },
  'vancouver':   { lat:  49.2827, lon: -123.1207, label: 'Vancouver',      flag: '🇨🇦', region: 'North America' },
  'mexico-city': { lat:  19.4326, lon:  -99.1332, label: 'Mexico City',    flag: '🇲🇽', region: 'North America' },
  // Europe
  'london':      { lat:  51.5074, lon:   -0.1278, label: 'London',         flag: '🇬🇧', region: 'Europe' },
  'manchester':  { lat:  53.4808, lon:   -2.2426, label: 'Manchester',     flag: '🇬🇧', region: 'Europe' },
  'paris':       { lat:  48.8566, lon:    2.3522, label: 'Paris',          flag: '🇫🇷', region: 'Europe' },
  'berlin':      { lat:  52.5200, lon:   13.4050, label: 'Berlin',         flag: '🇩🇪', region: 'Europe' },
  'frankfurt':   { lat:  50.1109, lon:    8.6821, label: 'Frankfurt',      flag: '🇩🇪', region: 'Europe' },
  'amsterdam':   { lat:  52.3676, lon:    4.9041, label: 'Amsterdam',      flag: '🇳🇱', region: 'Europe' },
  'rome':        { lat:  41.9028, lon:   12.4964, label: 'Rome',           flag: '🇮🇹', region: 'Europe' },
  'madrid':      { lat:  40.4168, lon:   -3.7038, label: 'Madrid',         flag: '🇪🇸', region: 'Europe' },
  'stockholm':   { lat:  59.3293, lon:   18.0686, label: 'Stockholm',      flag: '🇸🇪', region: 'Europe' },
  'warsaw':      { lat:  52.2297, lon:   21.0122, label: 'Warsaw',         flag: '🇵🇱', region: 'Europe' },
  'vienna':      { lat:  48.2082, lon:   16.3738, label: 'Vienna',         flag: '🇦🇹', region: 'Europe' },
  'zurich':      { lat:  47.3769, lon:    8.5417, label: 'Zurich',         flag: '🇨🇭', region: 'Europe' },
  'brussels':    { lat:  50.8503, lon:    4.3517, label: 'Brussels',       flag: '🇧🇪', region: 'Europe' },
  'prague':      { lat:  50.0755, lon:   14.4378, label: 'Prague',         flag: '🇨🇿', region: 'Europe' },
  // Asia / Pacific
  'tokyo':       { lat:  35.6762, lon:  139.6503, label: 'Tokyo',          flag: '🇯🇵', region: 'Asia / Pacific' },
  'osaka':       { lat:  34.6937, lon:  135.5023, label: 'Osaka',          flag: '🇯🇵', region: 'Asia / Pacific' },
  'seoul':       { lat:  37.5665, lon:  126.9780, label: 'Seoul',          flag: '🇰🇷', region: 'Asia / Pacific' },
  'singapore':   { lat:   1.3521, lon:  103.8198, label: 'Singapore',      flag: '🇸🇬', region: 'Asia / Pacific' },
  'hong-kong':   { lat:  22.3193, lon:  114.1694, label: 'Hong Kong',      flag: '🇭🇰', region: 'Asia / Pacific' },
  'shanghai':    { lat:  31.2304, lon:  121.4737, label: 'Shanghai',       flag: '🇨🇳', region: 'Asia / Pacific' },
  'bangkok':     { lat:  13.7563, lon:  100.5018, label: 'Bangkok',        flag: '🇹🇭', region: 'Asia / Pacific' },
  'jakarta':     { lat:  -6.2088, lon:  106.8456, label: 'Jakarta',        flag: '🇮🇩', region: 'Asia / Pacific' },
  'kl':          { lat:   3.1390, lon:  101.6869, label: 'Kuala Lumpur',   flag: '🇲🇾', region: 'Asia / Pacific' },
  'mumbai':      { lat:  19.0760, lon:   72.8777, label: 'Mumbai',         flag: '🇮🇳', region: 'Asia / Pacific' },
  'delhi':       { lat:  28.6139, lon:   77.2090, label: 'Delhi',          flag: '🇮🇳', region: 'Asia / Pacific' },
  'dubai':       { lat:  25.2048, lon:   55.2708, label: 'Dubai',          flag: '🇦🇪', region: 'Asia / Pacific' },
  'sydney':      { lat: -33.8688, lon:  151.2093, label: 'Sydney',         flag: '🇦🇺', region: 'Asia / Pacific' },
  'melbourne':   { lat: -37.8136, lon:  144.9631, label: 'Melbourne',      flag: '🇦🇺', region: 'Asia / Pacific' },
  'auckland':    { lat: -36.8485, lon:  174.7633, label: 'Auckland',       flag: '🇳🇿', region: 'Asia / Pacific' },
  // South America
  'sao-paulo':   { lat: -23.5505, lon:  -46.6333, label: 'São Paulo',      flag: '🇧🇷', region: 'South America' },
  'rio':         { lat: -22.9068, lon:  -43.1729, label: 'Rio de Janeiro', flag: '🇧🇷', region: 'South America' },
  'buenos-aires':{ lat: -34.6037, lon:  -58.3816, label: 'Buenos Aires',   flag: '🇦🇷', region: 'South America' },
  'bogota':      { lat:   4.7110, lon:  -74.0721, label: 'Bogotá',         flag: '🇨🇴', region: 'South America' },
  'lima':        { lat: -12.0464, lon:  -77.0428, label: 'Lima',           flag: '🇵🇪', region: 'South America' },
  'santiago':    { lat: -33.4489, lon:  -70.6693, label: 'Santiago',       flag: '🇨🇱', region: 'South America' },
  // Africa / Middle East
  'cairo':       { lat:  30.0444, lon:   31.2357, label: 'Cairo',          flag: '🇪🇬', region: 'Africa / Middle East' },
  'lagos':       { lat:   6.5244, lon:    3.3792, label: 'Lagos',          flag: '🇳🇬', region: 'Africa / Middle East' },
  'johannesburg':{ lat: -26.2041, lon:   28.0473, label: 'Johannesburg',   flag: '🇿🇦', region: 'Africa / Middle East' },
  'nairobi':     { lat:  -1.2921, lon:   36.8219, label: 'Nairobi',        flag: '🇰🇪', region: 'Africa / Middle East' },
  'tel-aviv':    { lat:  32.0853, lon:   34.7818, label: 'Tel Aviv',       flag: '🇮🇱', region: 'Africa / Middle East' },
  'riyadh':      { lat:  24.7136, lon:   46.6753, label: 'Riyadh',         flag: '🇸🇦', region: 'Africa / Middle East' },
};
function buildGeoScript(lat, lon) {
  return `(function(){
  var _r={coords:{latitude:${lat},longitude:${lon},accuracy:45,altitude:null,altitudeAccuracy:null,heading:null,speed:null},timestamp:Date.now()};
  var _g={getCurrentPosition:function(ok,err,opt){setTimeout(function(){ok(_r);},Math.random()*150+50);},watchPosition:function(ok,err,opt){setTimeout(function(){ok(_r);},Math.random()*150+50);return Math.floor(Math.random()*9999)+1;},clearWatch:function(){}};
  try{Object.defineProperty(Navigator.prototype,'geolocation',{get:function(){return _g;},configurable:true,enumerable:true});}catch(e){}
  try{Object.defineProperty(navigator,'geolocation',{get:function(){return _g;},configurable:true});}catch(e){}
})()`;
}

// ── IPC: Panels — detach/reattach BrowserView so HTML panels are visible ──────
// ── BV park / unpark helpers ─────────────────────────────────────────────────
// Park: slide the BV below the window bottom edge (y ≥ winH) while keeping it
// attached so the GPU compositor frame sink stays live (video keeps playing).
function _parkBV(bv) {
  if (!win || !bv) return;
  try {
    const [w, h] = win.getContentSize();
    // Keep full viewport dimensions — only move the BV off-screen vertically.
    // Using height:1 caused Blink's IntersectionObserver to report 0 intersection
    // for video players (viewport 1px tall), making YouTube/Twitch pause.
    // With the full height preserved the compositor keeps video alive naturally.
    bv.setBounds({ x: 0, y: h + 10, width: Math.max(w, 1), height: Math.max(h, 1) });
  } catch {}
}
// Unpark: restore the BV to its correct content-area bounds.
function _unparkBV(bv) {
  if (!win || !bv) return;
  try { setBounds(bv); } catch {}
}

// ── Shared panel-open helper ─────────────────────────────────────────────────
// WHY SLIDE-BELOW INSTEAD OF REMOVE:
//   removeBrowserView() detaches the RenderWidget from the GPU compositor’s
//   frame sink — a C++ operation that suspends the video decoder before any
//   JS can run. No JS flag or CLI switch prevents this.
//
//   Instead: slide the BV below the bottom edge of the window (y ≥ winH)
//   while keeping it ATTACHED. The compositor frame sink stays live, video
//   keeps playing, and the window’s full visible area is free for the
//   BrowserWindow HTML panels to render into. The snapshot element
//   (position:absolute; inset:0) covers the entire content area so the
//   user never sees the half-visible BV strip that the old resize caused.
async function _openPanel(tab) {
  if (!tab?.bv || tab.url === 'newtab') return;
  const bv = tab.bv;
  const wc = bv.webContents;
  if (wc.isDestroyed()) return;

  // Step 1: Inject keep-alive JS FIRST — sets _rbPanelOpen=true so video.pause()
  // is blocked before any resize fires. Must precede capturePage().
  await wc.executeJavaScript(PANEL_KEEP_ALIVE_JS).catch(() => {});
  if (!panelOpen) return;

  // Step 2–4: If page is still loading skip screenshot — capture would be blank
  // and capturePage() can take 300ms+, keeping the BV on top and hiding the panel.
  // Park immediately so the panel is visible right away.
  if (!wc.isLoading()) {
    // Capture screenshot at full bounds.
    try {
      const img = await wc.capturePage();
      if (img) tab.snapshot = 'data:image/jpeg;base64,' + img.toJPEG(60).toString('base64');
    } catch {}
    if (!panelOpen) return;

    // Send snapshot and wait for canvas draw ACK before parking.
    if (tab.snapshot) {
      send('panel:snapshot', tab.snapshot);
      await new Promise(resolve => {
        const t = setTimeout(resolve, 200);
        ipcMain.once('panel:snapshot:drawn', () => { clearTimeout(t); resolve(); });
      });
    }
    if (!panelOpen) return;
  }

  // Park BV off-screen. Canvas already drawn (or page was loading → no screenshot).
  _parkBV(bv);

  // Live capture loop removed — the initial screenshot is sufficient for the panel
  // overlay background. The continuous capturePage() loop was causing significant
  // GPU pressure and degrading video playback quality on sites like YouTube.
  tab._mediaKeepAlive = false;
}

ipcMain.on('panel:show', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});
// Send fresh privacy stats on demand (called when the privacy panel opens)
ipcMain.on('privacy:refresh', () => {
  const tab = tabMap.get(activeId);
  send('blocked:update', { total: totalBlocked, session: tab?.blocked || 0 });
});

ipcMain.on('panel:show:quick', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});
// Immediately park the active BV without taking a screenshot — used by settings page
// to hide web content behind the settings overlay without the async screenshot delay.
ipcMain.on('bv:park:fast', () => {
  const tab = tabMap.get(activeId);
  if (tab?.bv && !tab.bv.webContents.isDestroyed()) _parkBV(tab.bv);
});
ipcMain.on('panel:show:keepalive', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});
ipcMain.on('panel:show:fast', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});
ipcMain.on('panel:show:nowait', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});
ipcMain.on('panel:show:sync', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});
ipcMain.on('panel:show:instant', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});

// Resize BV to leave right-side room for the open panel (so panel HTML shows above BV)
ipcMain.on('panel:clip', (_, x) => {
  panelOpen  = true;
  panelClipX = Math.max(0, x || 0);
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab' && !tab.bv.webContents.isDestroyed()) {
    try { win.addBrowserView(tab.bv); } catch {}
    setBounds(tab.bv);
  }
});

// ── Omnibox dropdown — instant BV park/restore (no async screenshot) ────────
// _openPanel is async (capturePage before parking) which means the BV covers
// the suggestion list for ~300ms. These dedicated handlers park/restore
// synchronously so the dropdown is immediately visible above the BV.
ipcMain.on('omni:drop:show', () => {
  if (panelOpen) return; // panel already parked the BV — don't double-increment
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab' || tab.bv.webContents.isDestroyed()) return;
  // Show cached snapshot so the user sees the website instead of a dark background
  if (tab.snapshot) send('panel:snapshot', tab.snapshot);
  _omniParked = true;
  _parkBV(tab.bv);
});
ipcMain.on('omni:drop:hide', () => {
  if (panelOpen) return; // panel will restore the BV when it closes — don't decrement early
  if (!_omniParked) return; // nav:go already unparked — skip to avoid double-decrement
  _omniParked = false;
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab' || tab.bv.webContents.isDestroyed()) return;
  _unparkBV(tab.bv);
  send('panel:snapshot:clear'); // remove the snapshot overlay once BV is restored
});

ipcMain.on('panel:hide', async () => {
  panelOpen = false;
  _panelSeq = 0;    // invalidate any pending async panel:show:fast chains
  panelClipX = 0;   // always restore full BV width
  // Clear any pending panel:snapshot:drawn listener so it doesn't fire later
  ipcMain.removeAllListeners('panel:snapshot:drawn');
  const tab = tabMap.get(activeId);
  if (tab?._mediaKeepAlive) { tab._mediaKeepAlive = null; } // stops the capture loop
  if (tab?.bv && tab.url !== 'newtab') {
    // Unpark: decrement capturer count then restore full-width bounds
    _unparkBV(tab.bv);
    // Restore visibility overrides and dispatch resize so layouts rebuild
    tab.bv.webContents.executeJavaScript(PANEL_RESTORE_ALIVE_JS).catch(() => {});
    // Resume any media that was interrupted while the BV was parked
    tab.bv.webContents.executeJavaScript(`(function(){
      try{document.querySelectorAll('video,audio').forEach(function(m){
        if(m.paused&&m.readyState>0&&m.currentTime>0&&!m.ended){
          m.play().catch(function(){});
        }
      });}catch(e){}
    })()`).catch(() => {});
  }
  send('panel:snapshot:clear');
});

// ── History / dl-history overlay park (no screenshot needed — full-screen overlay) ─
ipcMain.on('history:open', async () => {
  panelOpen = true;
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab' || tab.bv.webContents.isDestroyed()) return;
  await tab.bv.webContents.executeJavaScript(PANEL_KEEP_ALIVE_JS).catch(() => {});
  _parkBV(tab.bv);
});

// ── Sidebar add-link popup ──────────────────────────────────────────────────
let _sidebarAddWin = null;

ipcMain.on('sidebar:modal:open', async (_, data) => {
  const tab = tabMap.get(activeId);
  const hasBV = tab?.bv && tab.url !== 'newtab' && !tab.bv.webContents.isDestroyed();
  if (hasBV) {
    const wc = tab.bv.webContents;
    // Capture screenshot at current full bounds
    try {
      const img = await Promise.race([
        wc.capturePage(),
        new Promise(r => setTimeout(() => r(null), 1000))
      ]);
      if (img) tab.snapshot = 'data:image/jpeg;base64,' + img.toJPEG(60).toString('base64');
    } catch {}
    // Send snapshot to renderer, wait for it to confirm canvas is drawn, then park.
    if (tab.snapshot) {
      send('panel:snapshot', tab.snapshot);
      await new Promise(resolve => {
        const t = setTimeout(resolve, 200);
        ipcMain.once('panel:snapshot:drawn', () => { clearTimeout(t); resolve(); });
      });
    }
    _parkBV(tab.bv);
  }

  // Open sidebar-add popup window
  if (_sidebarAddWin && !_sidebarAddWin.isDestroyed()) { _sidebarAddWin.focus(); return; }
  const [wx, wy] = win.getPosition();
  const [ww, wh] = win.getSize();
  const pw = 352, ph = 10;
  const px = Math.round(wx + ww / 2 - pw / 2);
  const py = Math.round(wy + wh / 2 - 100);

  _sidebarAddWin = new BrowserWindow({
    x: px, y: py, width: pw, height: ph,
    parent: win, frame: false, resizable: false, show: false,
    skipTaskbar: true, alwaysOnTop: true,
    transparent: true, backgroundColor: '#00000000', hasShadow: false,
    webPreferences: { nodeIntegration: true, contextIsolation: false },
  });

  _sidebarAddWin.loadFile(path.join(__dirname, 'assets', 'sidebar-add-popup.html'));

  const initData = data || {};
  _sidebarAddWin.webContents.on('did-finish-load', () => {
    if (!_sidebarAddWin || _sidebarAddWin.isDestroyed()) return;
    _sendThemeToPopup(_sidebarAddWin);
    _sidebarAddWin.webContents.send('sb:init', initData);
    _sidebarAddWin.webContents.executeJavaScript('document.body.scrollHeight').then(h => {
      if (_sidebarAddWin && !_sidebarAddWin.isDestroyed()) {
        _sidebarAddWin.setSize(pw, Math.max(140, h + 16));
        _sidebarAddWin.show();
      }
    }).catch(() => { _sidebarAddWin?.show(); });
  });

  _sidebarAddWin.on('closed', () => { _sidebarAddWin = null; });
});

function _closeSidebarAddPopup() {
  if (_sidebarAddWin && !_sidebarAddWin.isDestroyed()) {
    try { _sidebarAddWin.close(); } catch {}
  }
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab') {
    try { if (tab.bv.webContents.isDestroyed()) return; } catch { return; }
    _unparkBV(tab.bv);
  }
  send('panel:snapshot:clear');
}

ipcMain.on('sb-add:submit', (_, { url, title }) => {
  // Add to sidebar sites
  const sites = [...(settings.sidebarSites || [])];
  if (!sites.some(s => s.url === url)) {
    sites.push({ url, title });
    settings.sidebarSites = sites;
    save(F.settings, settings);
    send('settings:set', settings);
  }
  _closeSidebarAddPopup();
});

ipcMain.on('sb-add:cancel', () => {
  _closeSidebarAddPopup();
});

ipcMain.on('sidebar:modal:close', () => {
  _closeSidebarAddPopup();
});

ipcMain.on('sidebar:toggle', (_, show) => {
  sidebarOn = !!show;
  // Update bounds for all tabs so sidebar offset is applied immediately
  if (!panelOpen) {
    for (const t of tabMap.values()) {
      if (t.bv && t.url !== 'newtab' && !t.bv.webContents.isDestroyed()) {
        try { setBounds(t.bv); } catch {}
      }
    }
  }
});

ipcMain.on('vtab:toggle', (_, on) => {
  verticalTabsOn = !!on;
  if (!panelOpen) {
    for (const t of tabMap.values()) {
      if (t.bv && !t.bv.webContents.isDestroyed()) {
        try { setBounds(t.bv); } catch {}
      }
    }
  }
});

ipcMain.on('vtab:resize', (_, w) => {
  VTAB_W = Math.max(140, Math.min(420, Math.round(w)));
  if (!panelOpen) {
    for (const t of tabMap.values()) {
      if (t.bv && !t.bv.webContents.isDestroyed()) {
        try { setBounds(t.bv); } catch {}
      }
    }
  }
});

// ── IPC: Snip tool ────────────────────────────────────────────────────────────
ipcMain.on('snip:start', () => {
  panelOpen = true;
  const seq = ++_panelSeq;
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab') { send('snip:ready', null); return; }
  const _sbv = tab.bv;
  const _swc = _sbv.webContents;
  // Inject keep-alive guard FIRST so video never pauses during capture or park.
  _swc.executeJavaScript(PANEL_KEEP_ALIVE_JS).catch(() => {}).finally(() => {
    if (!panelOpen || _panelSeq !== seq) return;
    _swc.capturePage().then(img => {
      if (!panelOpen || _panelSeq !== seq) return;
      _parkBV(_sbv);
      send('snip:ready', img.toDataURL());
    }).catch(() => {
      if (!panelOpen || _panelSeq !== seq) return;
      _parkBV(_sbv);
      send('snip:ready', null);
    });
  });
});
ipcMain.on('snip:cancel', () => {
  panelOpen = false;
  _panelSeq = 0;
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab') try { win.addBrowserView(tab.bv); setBounds(tab.bv); } catch {}
});
ipcMain.on('snip:save', async (_, dataURL) => {
  panelOpen = false;
  _panelSeq = 0;
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab') try { win.addBrowserView(tab.bv); setBounds(tab.bv); } catch {}
  try {
    const buf = Buffer.from(dataURL.replace(/^data:image\/png;base64,/, ''), 'base64');
    const ts  = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const def = path.join(app.getPath('pictures'), `snip-${ts}.png`);
    const { canceled, filePath: fp } = await dialog.showSaveDialog(win, {
      title: 'Save Snip', defaultPath: def,
      filters: [{ name: 'PNG Image', extensions: ['png'] }],
    });
    if (!canceled && fp) fs.writeFile(fp, buf, err => send('toast', err ? 'Failed to save snip' : 'Snip saved', err ? 'err' : 'teal'));
  } catch {}
});

// ── IPC: Bookmarks ────────────────────────────────────────────────────────────
ipcMain.on('bookmark:add', (_, { url, title, favicon }) => {
  bookmarks.unshift({ id: Date.now(), url, title, favicon, ts: Date.now() });
  save(F.bookmarks, bookmarks);
  send('bookmarks:set', bookmarks);
});
ipcMain.on('bookmark:remove', (_, id) => {
  bookmarks = bookmarks.filter(b => b.id !== id);
  save(F.bookmarks, bookmarks);
  send('bookmarks:set', bookmarks);
});
// Bulk import bookmarks from external source (setup import step)
ipcMain.on('bookmarks:bulk-add', (_, items) => {
  if (!Array.isArray(items) || !items.length) return;
  const existingUrls = new Set(bookmarks.map(b => b.url));
  const newOnes = items
    .filter(b =>
      b && typeof b.url === 'string' && typeof b.title === 'string' &&
      // Strict: only http/https URLs — never allow javascript:, file:, data:, etc.
      /^https?:\/\//i.test(b.url) &&
      b.url.length < 2048 &&
      !existingUrls.has(b.url)
    )
    .map((b, i) => ({
      id: Date.now() + i,
      url: b.url,
      // Sanitize title — strip any HTML/control chars
      title: String(b.title).replace(/[\x00-\x1f<>"']/g, '').slice(0, 300) || 'Bookmark',
      favicon: null, ts: Date.now()
    }));
  if (!newOnes.length) return;
  bookmarks.push(...newOnes);
  save(F.bookmarks, bookmarks);
  send('bookmarks:set', bookmarks);
});

// ── Helpers: LZ4 block decoder (for Firefox mozlz4 bookmark backups) ──────────
function lz4BlockDecode(src, outputSize) {
  const dst = Buffer.alloc(outputSize);
  let si = 0, di = 0;
  while (si < src.length) {
    const token = src[si++];
    let litLen = token >>> 4;
    if (litLen === 15) { let x; do { x = src[si++]; litLen += x; } while (x === 255); }
    src.copy(dst, di, si, si + litLen); si += litLen; di += litLen;
    if (si >= src.length) break;
    const offset = src[si] | (src[si + 1] << 8); si += 2;
    let matchLen = (token & 0xf) + 4;
    if ((token & 0xf) === 15) { let x; do { x = src[si++]; matchLen += x; } while (x === 255); }
    const ms = di - offset;
    for (let k = 0; k < matchLen; k++) dst[di++] = dst[ms + k];
  }
  return dst.slice(0, di);
}
function decodeMozlz4(buf) {
  if (buf.slice(0, 8).toString('binary') !== 'mozLz40\0') throw new Error('Not mozlz4');
  const uncompressedSize = buf.readUInt32LE(8);
  // Cap at 64 MB — a real Firefox bookmark file is never this large.
  // Prevents DoS via malformed/crafted mozlz4 file.
  if (uncompressedSize > 64 * 1024 * 1024) throw new Error('mozlz4: output too large, refusing to decode');
  return lz4BlockDecode(buf.slice(12), uncompressedSize);
}
function extractFirefoxBookmarks(node, out = []) {
  if (!node) return out;
  if (node.type === 'text/x-moz-place' && node.uri && node.title &&
      !/^(place:|javascript:|vbscript:)/i.test(node.uri) && /^https?:\/\//i.test(node.uri)) {
    out.push({ title: String(node.title).slice(0, 500), url: node.uri });
  }
  if (Array.isArray(node.children)) node.children.forEach(c => extractFirefoxBookmarks(c, out));
  return out;
}
function findFirefoxBookmarkBackup() {
  const home = os.homedir();
  const pl   = process.platform;
  const base = pl === 'win32'  ? path.join(os.homedir(), 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles')
             : pl === 'darwin' ? path.join(home, 'Library', 'Application Support', 'Firefox', 'Profiles')
                               : path.join(home, '.mozilla', 'firefox');
  return findMozillaBookmarkBackup([base]);
}
// Generic finder: searches a list of profile-base directories for mozlz4 backups.
// Handles all Firefox forks that use the same profile layout.
function findMozillaBookmarkBackup(bases) {
  for (const base of (Array.isArray(bases) ? bases : [bases])) {
    if (!base) continue;
    try {
      if (!fs.existsSync(base)) continue;
      const profiles = fs.readdirSync(base);
      for (const prof of profiles) {
        if (prof === 'Crash Reports' || prof === 'crash-reports') continue;
        const bbDir = path.join(base, prof, 'bookmarkbackups');
        try {
          const files = fs.readdirSync(bbDir).filter(f => f.endsWith('.jsonlz4') || f.endsWith('.baklz4'));
          if (!files.length) continue;
          // Use the most recently modified backup
          const best = files.map(f => {
            try { return { f, mt: fs.statSync(path.join(bbDir, f)).mtimeMs }; } catch { return null; }
          }).filter(Boolean).sort((a, b) => b.mt - a.mt)[0];
          if (best) return path.join(bbDir, best.f);
        } catch {}
      }
    } catch {}
  }
  return null;
}
// Build profile-base path list for a Firefox-family browser given its app-data dir name(s)
function getMozProfileBases(winNames, macNames, linuxNames) {
  const home = os.homedir();
  const pl   = process.platform;
  const roaming = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
  const local   = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
  if (pl === 'win32')  return winNames.map(n => path.join(roaming, n));
  if (pl === 'darwin') return macNames.map(n => path.join(home, 'Library', 'Application Support', n));
  return linuxNames.map(n => path.join(home, n));
}
function* walkDir(dir) {
  try {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) yield* walkDir(full);
      else yield full;
    }
  } catch {}
}

// ── Helper: find Chromium Bookmarks file across all profiles ──────────────────
// chromiumPaths stores paths like: .../User Data/Default/Bookmarks
// If the user's active profile isn't 'Default', we scan siblings too.
function _findChromiumBookmarks(defaultPath) {
  if (!defaultPath) return null;
  try {
    if (fs.existsSync(defaultPath)) return defaultPath;
    // Walk up two levels to get the User Data directory
    const userData = path.dirname(path.dirname(defaultPath));
    if (!fs.existsSync(userData)) return null;
    const entries = fs.readdirSync(userData, { withFileTypes: true });
    for (const ent of entries) {
      if (!ent.isDirectory()) continue;
      if (!/^(Default|Profile \d+|Guest Profile|System Profile)$/.test(ent.name)) continue;
      const bmPath = path.join(userData, ent.name, 'Bookmarks');
      if (fs.existsSync(bmPath)) return bmPath;
    }
  } catch {}
  return null;
}

// ── Windows: register as default browser in system Default Apps ───────────────
// Follows the exact same registry structure that Chrome/Edge use so Windows
// 10/11 recognises Lander Browser in Settings › Default Apps.
//
// Structure (all under HKCU so no admin required):
//   HKCU\Software\Classes\LanderBrowserHTML           ← ProgID (URL + file handler)
//   HKCU\Software\Clients\StartMenuInternet\Lander Browser   ← StartMenuInternet tree
//   HKCU\Software\RegisteredApplications           ← makes it appear in Default Apps UI
function _registerWindowsDefaultBrowser() {
  if (process.platform !== 'win32') return;
  try {
    const { execSync } = require('child_process');
    const exePath = app.getPath('exe');
    const progID  = 'LanderBrowserHTML'; // single ProgID for both URL + file types (mirrors ChromeHTML)
    const appKey  = `Software\\Clients\\StartMenuInternet\\Lander Browser`;
    const capKey  = `${appKey}\\Capabilities`;
    const clsKey  = `Software\\Classes\\${progID}`;

    const regSZ = (hive, key, name, val) => {
      const escaped = String(val).replace(/"/g, '\\"');
      const n = name === '' ? '/ve' : `/v "${name}"`;
      execSync(`reg add "${hive}\\${key}" ${n} /t REG_SZ /d "${escaped}" /f`,
               { windowsHide: true, stdio: 'ignore' });
    };
    const regDW = (hive, key, name, val) => {
      execSync(`reg add "${hive}\\${key}" /v "${name}" /t REG_DWORD /d "${val}" /f`,
               { windowsHide: true, stdio: 'ignore' });
    };

    // ── ProgID — describes how to open URLs and HTML files ──────────────────
    regSZ('HKCU', clsKey, '', 'Lander Browser HTML Document');
    regSZ('HKCU', `${clsKey}\\DefaultIcon`, '', `"${exePath}",0`);
    regSZ('HKCU', `${clsKey}\\shell\\open\\command`, '', `"${exePath}" "%1"`);
    // Mark as a URL handler for http + https
    regSZ('HKCU', clsKey, 'URL Protocol', '');

    // ── StartMenuInternet tree — required so Windows lists the app ───────────
    regSZ('HKCU', appKey, '', 'Lander Browser');
    regSZ('HKCU', `${appKey}\\DefaultIcon`, '', `"${exePath}",0`);
    regSZ('HKCU', `${appKey}\\shell\\open\\command`, '', `"${exePath}"`);
    regDW('HKCU', `${appKey}\\InstallInfo`, 'IconsVisible', 1);
    regSZ('HKCU', `${appKey}\\StartMenu`, '', 'Lander Browser');

    // ── Capabilities — what Windows reads from RegisteredApplications ────────
    regSZ('HKCU', capKey, 'ApplicationName', 'Lander Browser');
    regSZ('HKCU', capKey, 'ApplicationIcon', `"${exePath}",0`);
    regSZ('HKCU', capKey, 'ApplicationDescription', 'Privacy-first browser — built-in ad blocking, no tracking');
    // URL associations
    regSZ('HKCU', `${capKey}\\URLAssociations`, 'ftp',   progID);
    regSZ('HKCU', `${capKey}\\URLAssociations`, 'http',  progID);
    regSZ('HKCU', `${capKey}\\URLAssociations`, 'https', progID);
    // File associations
    regSZ('HKCU', `${capKey}\\FileAssociations`, '.htm',   progID);
    regSZ('HKCU', `${capKey}\\FileAssociations`, '.html',  progID);
    regSZ('HKCU', `${capKey}\\FileAssociations`, '.xhtml', progID);
    regSZ('HKCU', `${capKey}\\FileAssociations`, '.pdf',   progID);

    // ── RegisteredApplications — the entry that makes it appear in Default Apps
    // Value must be the path WITHOUT the HKCU\ prefix
    regSZ('HKCU', 'Software\\RegisteredApplications', 'Lander Browser', capKey);
  } catch { /* fail silently — restricted environments */ }
}

// ── IPC: Open external URL in system browser ──────────────────────────────────
ipcMain.on('open-external', (_, url) => {
  if (typeof url === 'string' && /^https?:\/\//i.test(url)) {
    shell.openExternal(url).catch(() => {});
  }
});

// ── IPC: Default browser ──────────────────────────────────────────────────────
ipcMain.on('browser:set-default', () => {
  app.setAsDefaultProtocolClient('https');
  app.setAsDefaultProtocolClient('http');
  app.setAsDefaultProtocolClient('ftp');
  if (process.platform === 'win32') {
    _registerWindowsDefaultBrowser();
    shell.openExternal('ms-settings:defaultapps').catch(() => {});
  } else if (process.platform === 'darwin') {
    shell.openExternal('x-apple.systempreferences:com.apple.preference.general').catch(() => {});
  }
});
ipcMain.handle('browser:is-default', () => app.isDefaultProtocolClient('https'));

// Dismiss default browser prompt — never ask again
ipcMain.on('default-browser-prompt:dismiss', () => {
  settings = { ...settings, defaultBrowserPromptDismissed: true };
  save(F.settings, settings);
});

// ── IPC: Browser data import ──────────────────────────────────────────────────
// Strict allowlist — never let the renderer supply an arbitrary string to a file-read path.
const _MOZ_BROWSER_IDS = new Set(['firefox','librewolf','zen','waterfox','floorp','palemoon','basilisk','iceweasel']);
const _CHROME_BROWSER_IDS = new Set(['chrome','edge','brave','opera','vivaldi','arc','thorium','chromium','opera-gx','yandex']);
const _SPECIAL_IDS = new Set(['safari','ie']);

function _buildChromiumPaths() {
  const home = os.homedir();
  const pl   = process.platform;
  const local = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
  const roam  = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
  const bm = n => `${n}${path.sep}Bookmarks`; // append Bookmarks filename
  function w(p) { return path.join(local, p, 'Bookmarks'); }
  function m(p) { return path.join(home, 'Library', 'Application Support', p, 'Bookmarks'); }
  function l(p) { return path.join(home, p, 'Bookmarks'); }
  const table = {
    chrome:    { win: w('Google\\Chrome\\User Data\\Default'),   mac: m('Google/Chrome/Default'),         lin: l('.config/google-chrome/Default') },
    edge:      { win: w('Microsoft\\Edge\\User Data\\Default'),  mac: m('Microsoft Edge/Default'),         lin: l('.config/microsoft-edge/Default') },
    brave:     { win: w('BraveSoftware\\Brave-Browser\\User Data\\Default'), mac: m('BraveSoftware/Brave-Browser/Default'), lin: l('.config/BraveSoftware/Brave-Browser/Default') },
    opera:     { win: path.join(roam, 'Opera Software', 'Opera Stable', 'Bookmarks'), mac: m('com.operasoftware.Opera'), lin: l('.config/opera') + '/Bookmarks' },
    'opera-gx':{ win: path.join(roam, 'Opera Software', 'Opera GX Stable', 'Bookmarks'), mac: m('com.operasoftware.OperaGX'), lin: l('.config/opera') + '/Bookmarks' },
    vivaldi:   { win: w('Vivaldi\\User Data\\Default'),          mac: m('Vivaldi/Default'),                lin: l('.config/vivaldi/Default') },
    arc:       { win: w('Arc\\User Data\\Default'),              mac: m('Arc/User Data/Default'),          lin: null },
    thorium:   { win: w('Thorium\\User Data\\Default'),          mac: m('Thorium/Default'),                lin: l('.config/thorium/Default') },
    chromium:  { win: w('Chromium\\User Data\\Default'),         mac: m('Chromium/Default'),               lin: l('.config/chromium/Default') },
    yandex:    { win: w('Yandex\\YandexBrowser\\User Data\\Default'), mac: m('Yandex/YandexBrowser/Default'), lin: l('.config/yandex-browser-beta/Default') },
  };
  const result = {};
  for (const [id, paths] of Object.entries(table)) {
    result[id] = pl === 'win32' ? paths.win : pl === 'darwin' ? paths.mac : paths.lin;
  }
  return result;
}
function _buildMozillaForkBases() {
  // Each entry: list of profile BASE directories to search
  return {
    firefox:   getMozProfileBases(['Mozilla\\Firefox\\Profiles'], ['Firefox/Profiles'], ['.mozilla/firefox']),
    librewolf: getMozProfileBases(['LibreWolf\\Profiles'], ['LibreWolf/Profiles'], ['.librewolf']),
    zen:       getMozProfileBases(['Zen\\Profiles', 'Zen Browser\\Profiles'], ['Zen Browser/Profiles'], ['.zen']),
    waterfox:  getMozProfileBases(['Waterfox\\Profiles'], ['Waterfox/Profiles'], ['.waterfox']),
    floorp:    getMozProfileBases(['Floorp\\Profiles'], ['Floorp/Profiles'], ['.floorp']),
    palemoon:  getMozProfileBases(['Moonchild Productions\\Pale Moon\\Profiles'], ['Pale Moon/Profiles'], ['.moonchild productions/pale moon']),
    basilisk:  getMozProfileBases(['Moonchild Productions\\Basilisk\\Profiles'], ['Basilisk/Profiles'], ['.moonchild productions/basilisk']),
    iceweasel: getMozProfileBases(['Iceweasel\\Profiles'], ['Iceweasel/Profiles'], ['.iceweasel']),
  };
}

ipcMain.handle('setup:detect-browsers', () => {
  const home = os.homedir();
  const pl   = process.platform;
  const exists = p => { try { return !!p && fs.existsSync(p); } catch { return false; } };
  const chromiumPaths = _buildChromiumPaths();
  const mozBases      = _buildMozillaForkBases();

  const BROWSERS = [
    // ── Chromium family ──
    { id: 'chrome',    name: 'Google Chrome' },
    { id: 'edge',      name: 'Microsoft Edge' },
    { id: 'brave',     name: 'Brave' },
    { id: 'opera',     name: 'Opera' },
    { id: 'opera-gx',  name: 'Opera GX' },
    { id: 'vivaldi',   name: 'Vivaldi' },
    { id: 'arc',       name: 'Arc' },
    { id: 'thorium',   name: 'Thorium' },
    { id: 'chromium',  name: 'Chromium' },
    { id: 'yandex',    name: 'Yandex Browser' },
    // ── Firefox family (all use mozlz4 format) ──
    { id: 'firefox',   name: 'Firefox',   isFirefox: true },
    { id: 'librewolf', name: 'LibreWolf', isFirefox: true },
    { id: 'zen',       name: 'Zen Browser',isFirefox: true },
    { id: 'waterfox',  name: 'Waterfox',  isFirefox: true },
    { id: 'floorp',    name: 'Floorp',    isFirefox: true },
    { id: 'palemoon',  name: 'Pale Moon', isFirefox: true },
    { id: 'basilisk',  name: 'Basilisk',  isFirefox: true },
    // ── Other ──
    ...(pl === 'darwin' ? [{ id: 'safari', name: 'Safari' }] : []),
    ...(pl === 'win32'  ? [{ id: 'ie',     name: 'IE Favorites' }] : []),
  ];

  return BROWSERS
    .map(b => {
      let found = false;
      if (_CHROME_BROWSER_IDS.has(b.id)) {
        found = !!_findChromiumBookmarks(chromiumPaths[b.id]);
      } else if (_MOZ_BROWSER_IDS.has(b.id)) {
        found = !!findMozillaBookmarkBackup(mozBases[b.id] || []);
      } else if (b.id === 'safari') {
        found = exists(path.join(home, 'Library', 'Safari', 'Bookmarks.plist'));
      } else if (b.id === 'ie') {
        found = exists(path.join(home, 'Favorites'));
      }
      return { id: b.id, name: b.name, found, isFirefox: !!b.isFirefox };
    });
});

ipcMain.handle('browser:import-bookmarks', async (_, browserId) => {
  // Strict allowlist — prevent renderer from supplying an arbitrary browserId
  if (typeof browserId !== 'string' ||
      (!_MOZ_BROWSER_IDS.has(browserId) && !_CHROME_BROWSER_IDS.has(browserId) && !_SPECIAL_IDS.has(browserId))) {
    return { error: 'Unknown browser' };
  }

  const home = os.homedir();
  const pl   = process.platform;

  // ── Firefox family (all use mozlz4 bookmark backups) ─────────────────────
  if (_MOZ_BROWSER_IDS.has(browserId)) {
    try {
      const mozBases  = _buildMozillaForkBases();
      const bakPath   = findMozillaBookmarkBackup(mozBases[browserId] || []);
      if (!bakPath) return { error: `No ${browserId} bookmark backup found` };
      const buf  = fs.readFileSync(bakPath);
      const json = JSON.parse(decodeMozlz4(buf).toString('utf8'));
      const bms  = extractFirefoxBookmarks(json);
      return { bookmarks: bms, count: bms.length };
    } catch (e) { return { error: e.message }; }
  }

  // ── Internet Explorer / Edge Legacy (Favorites folder) ──────────────────
  if (browserId === 'ie') {
    try {
      const favDir = path.join(home, 'Favorites');
      const bms = [];
      for (const fpath of walkDir(favDir)) {
        if (!fpath.toLowerCase().endsWith('.url')) continue;
        try {
          const txt = fs.readFileSync(fpath, 'utf8');
          const m = txt.match(/^\s*URL\s*=\s*(.+)/im);
          if (!m) continue;
          const url = m[1].trim();
          if (!/^https?:\/\//i.test(url)) continue;
          bms.push({ title: path.basename(fpath, '.url'), url });
        } catch {}
      }
      return { bookmarks: bms, count: bms.length };
    } catch (e) { return { error: e.message }; }
  }

  // ── Safari (macOS only) ────────────────────────────────────────────────────
  if (browserId === 'safari') {
    try {
      if (pl !== 'darwin') return { error: 'Safari is only on macOS' };
      const plistPath = path.join(home, 'Library', 'Safari', 'Bookmarks.plist');
      const { execSync } = require('child_process');
      const jsonStr = execSync(`plutil -convert json -o - "${plistPath}"`).toString('utf8');
      const root    = JSON.parse(jsonStr);
      const bms     = [];
      function walkSafari(node) {
        if (!node) return;
        if (node.WebBookmarkType === 'WebBookmarkTypeLeaf' && node.URLString && node.URIDictionary?.title) {
          if (/^https?:\/\//i.test(node.URLString))
            bms.push({ title: node.URIDictionary.title, url: node.URLString });
        }
        const children = node.Children || node.WebBookmarkChildren;
        if (Array.isArray(children)) children.forEach(walkSafari);
      }
      walkSafari(root);
      return { bookmarks: bms, count: bms.length };
    } catch (e) { return { error: e.message }; }
  }

  // ── Chromium-based browsers ────────────────────────────────────────────────
  const defaultBmPath = _buildChromiumPaths()[browserId];
  const bmPath = _findChromiumBookmarks(defaultBmPath);
  if (!bmPath) return { error: `${browserId} not found or has no bookmarks file` };
  try {
    const raw = JSON.parse(fs.readFileSync(bmPath, 'utf8'));
    const bms = [];
    function extractChrome(node) {
      if (!node) return;
      if (node.type === 'url' && node.url && node.name && /^https?:\/\//i.test(node.url))
        bms.push({ title: node.name, url: node.url });
      if (Array.isArray(node.children)) node.children.forEach(extractChrome);
    }
    ['bookmark_bar', 'other', 'synced'].forEach(k => extractChrome((raw.roots || {})[k]));
    return { bookmarks: bms, count: bms.length };
  } catch (e) { return { error: e.message }; }
});

ipcMain.handle('browser:import-history', async (_, browserId) => {
  if (typeof browserId !== 'string' ||
      (!_MOZ_BROWSER_IDS.has(browserId) && !_CHROME_BROWSER_IDS.has(browserId))) {
    return { error: 'Unknown browser', items: [] };
  }
  const tmpDir = path.join(app.getPath('temp'), 'raw-hist-import');
  try {
    let histFile = null;
    if (_CHROME_BROWSER_IDS.has(browserId)) {
      const bmPath = _findChromiumBookmarks(_buildChromiumPaths()[browserId]);
      if (bmPath) {
        const hp = path.join(path.dirname(bmPath), 'History');
        if (fs.existsSync(hp)) histFile = hp;
      }
    } else if (_MOZ_BROWSER_IDS.has(browserId)) {
      const mozBases = _buildMozillaForkBases();
      const bases = mozBases[browserId] || [];
      outer: for (const base of bases) {
        if (!fs.existsSync(base)) continue;
        for (const d of fs.readdirSync(base)) {
          const p = path.join(base, d, 'places.sqlite');
          if (fs.existsSync(p)) { histFile = p; break outer; }
        }
      }
    }
    if (!histFile) return { error: 'History file not found', items: [] };
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
    const tmpFile = path.join(tmpDir, 'h_' + Date.now());
    fs.copyFileSync(histFile, tmpFile);
    const buf = fs.readFileSync(tmpFile);
    try { fs.unlinkSync(tmpFile); } catch {}
    // Scan SQLite binary for embedded URL strings (stored as UTF-8 text)
    const text = buf.toString('latin1');
    const urlRx = /https?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]{8,600}/g;
    const seen = new Set();
    const items = [];
    let m;
    while ((m = urlRx.exec(text)) !== null) {
      let url = m[0].replace(/[^a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+$/, '');
      if (!url || seen.has(url) || url.length < 12) continue;
      seen.add(url);
      items.push({ url, title: url, ts: Date.now() });
      if (items.length >= 10000) break;
    }
    return { items, count: items.length };
  } catch (e) { return { error: e.message, items: [] }; }
});

ipcMain.on('history:bulk-add', (_, items) => {
  if (!Array.isArray(items)) return;
  const existing = new Set(history.map(h => h.url));
  let added = 0;
  for (const item of items) {
    if (!item.url || existing.has(item.url)) continue;
    existing.add(item.url);
    history.push({ url: item.url, title: item.title || item.url, ts: item.ts || Date.now() });
    added++;
  }
  if (added > 0) {
    history.sort((a, b) => (b.ts || 0) - (a.ts || 0));
    save(F.history, history);
    send('history:set', history);
  }
});

// ── IPC: History ──────────────────────────────────────────────────────────────
ipcMain.on('history:clear', () => {
  history = [];
  save(F.history, []);
  send('history:set', []);
});

ipcMain.on('history:remove', (_, { url, ts }) => {
  history = history.filter(h => !(h.ts === ts && h.url === url));
  save(F.history, history);
  send('history:set', history);
});

ipcMain.on('history:clear-since', (_, { since }) => {
  history = history.filter(h => h.ts < since);
  save(F.history, history);
  send('history:set', history);
});

// ── IPC: Downloads ────────────────────────────────────────────────────────────
ipcMain.on('downloads:clear', () => {
  downloads = downloads.filter(d => d.state === 'progressing');
  save(F.downloads, []);
  send('downloads:update', downloads);
});

ipcMain.handle('downloads:pick-dir', async () => {
  const r = await dialog.showOpenDialog(win, { properties: ['openDirectory'] });
  if (r.canceled) return null;
  const chosen = r.filePaths[0];
  settings.downloadPath = chosen;
  save(F.settings, settings);
  send('settings:set', settings);
  return chosen;
});
// ── Limiter Tool IPC ──────────────────────────────────────────────────────────
ipcMain.handle('limiter:totalmem', () => require('os').totalmem());

ipcMain.on('limiter:network', (_, { throttle, kbps }) => {
  try {
    const ses = session.fromPartition('persist:main');
    if (!throttle) {
      ses.disableNetworkEmulation();
    } else {
      const bps = (kbps || 0) * 1024;
      ses.enableNetworkEmulation({ downloadThroughput: bps, uploadThroughput: Math.round(bps * 0.4) });
    }
  } catch(e) {}
});
ipcMain.on('limiter:cpu', (_, { level, pct }) => {
  // level: 0=below normal, 1=normal, 2=above normal
  // pct: optional percentage (5-100), used to derive level if not given
  try {
    const p = typeof pct === 'number' ? pct : (level === 0 ? 20 : level === 2 ? 90 : 50);
    const derivedLevel = p <= 33 ? 0 : p <= 75 ? 1 : 2;
    const useLevel = typeof level === 'number' ? level : derivedLevel;
    if (process.platform === 'win32') {
      const { exec } = require('child_process');
      const pid = process.pid;
      const wmiPri = useLevel === 0 ? 'Below Normal' : useLevel === 2 ? 'Above Normal' : 'Normal';
      exec(`wmic process where ProcessId=${pid} CALL setpriority "${wmiPri}"`, () => {});
    }
  } catch(e) {}
});
ipcMain.on('limiter:ram', (_, { level, limitMb }) => {
  try {
    const mb = typeof limitMb === 'number' ? limitMb : (level > 0 ? 512 : 0);
    if (mb === 0) return;
    // Force V8 garbage collection (best-effort with --expose-gc)
    if (global.gc) global.gc();
    // Check current RSS against limit and ask renderers to free memory
    const rssMb = Math.round(process.memoryUsage().rss / (1024 * 1024));
    for (const [, tab] of tabMap) {
      if (tab.bv && tab.bv.webContents && !tab.bv.webContents.isDestroyed()) {
        if (rssMb > mb) tab.bv.webContents.invalidate();
      }
    }
  } catch(e) {}
});

ipcMain.on('downloads:pause', (_, id) => {
  const item = _downloadItems.get(id);
  if (item && !item.isPaused()) { item.pause(); }
  const entry = downloads.find(d => d.id === id);
  if (entry) { entry.paused = true; send('downloads:update', downloads); }
});
ipcMain.on('downloads:resume', (_, id) => {
  const item = _downloadItems.get(id);
  if (item && item.isPaused()) { item.resume(); }
  const entry = downloads.find(d => d.id === id);
  if (entry) { entry.paused = false; send('downloads:update', downloads); }
});
ipcMain.on('downloads:cancel', (_, id) => {
  const item = _downloadItems.get(id);
  if (item) { item.cancel(); }
  downloads = downloads.filter(d => d.id !== id);
  _downloadItems.delete(id);
  send('downloads:update', downloads);
});
ipcMain.on('downloads:open',   (_, p) => {
  // Validate: must be an absolute path to an existing file in a safe location.
  // Never open paths that start with ~, contain .. traversal, or point outside home/downloads.
  if (typeof p !== 'string') return;
  try {
    const resolved = path.resolve(p);
    const safe = [
      os.homedir(),
      app.getPath('downloads'),
      app.getPath('temp'),
    ].some(d => resolved.startsWith(path.resolve(d) + path.sep) || resolved === path.resolve(d));
    if (!safe || !fs.existsSync(resolved)) return;
    shell.openPath(resolved).catch(() => {});
  } catch {}
});
ipcMain.on('downloads:reveal', (_, p) => {
  if (typeof p !== 'string') return;
  try {
    const resolved = path.resolve(p);
    const safe = [
      os.homedir(),
      app.getPath('downloads'),
      app.getPath('temp'),
    ].some(d => resolved.startsWith(path.resolve(d) + path.sep) || resolved === path.resolve(d));
    if (!safe) return;
    shell.showItemInFolder(resolved);
  } catch {}
});

// ── IPC: Settings ─────────────────────────────────────────────────────────────
ipcMain.on('settings:reset', () => {
  settings = { ...DEF_SETTINGS };
  save(F.settings, settings);
  send('settings:set', settings);
  setTimeout(() => _broadcastThemeToPopups(), 50);
  send('toast', 'Settings reset to defaults', 'teal');
});
ipcMain.on('settings:set', (_, patch) => {
  settings = { ...settings, ...patch };
  save(F.settings, settings);
  send('settings:set', settings);
  // Broadcast theme to all open popups when theme changes
  if ('theme' in patch || 'accentColor' in patch) {
    setTimeout(() => _broadcastThemeToPopups(), 50); // small delay so main window CSS updates first
  }
  // Clear block cache when adblock settings change so new rules take effect immediately
  if ('adblockEnabled' in patch || 'blockingLevel' in patch) {
    try { _blockCache && _blockCache.clear(); } catch {}
  }

  // Update chrome height for compact mode — keeps BrowserView flush with nav bar
  if ('compactMode' in patch) {
    CHROME_H = settings.compactMode ? 72 : 82;
    // Only reposition BVs when panels/settings are NOT open — otherwise the
    // parked BV would jump back into the viewport and paint on top of the overlay.
    if (!panelOpen) {
      for (const t of tabMap.values()) {
        if (t.bv && t.url !== 'newtab' && !t.bv.webContents.isDestroyed()) {
          try { setBounds(t.bv); } catch {}
        }
      }
    }
  }

  if ('verticalTabs' in patch) {
    verticalTabsOn = !!settings.verticalTabs;
    if (!panelOpen) {
      for (const t of tabMap.values()) {
        if (t.bv && t.url !== 'newtab' && !t.bv.webContents.isDestroyed()) {
          try { setBounds(t.bv); } catch {}
        }
      }
    }
  }

  if ('preferredLanguage' in patch && patch.preferredLanguage) {
    applyPreferredLanguage(patch.preferredLanguage);
  }

  if ('spoofUserAgent' in patch && settings.spoofUserAgent) {
    const ua = settings.uaRotate
      ? _UA_ROTATE_POOL[Math.floor(Math.random() * _UA_ROTATE_POOL.length)]
      : SPOOF_UA;
    for (const t of tabMap.values()) { if (!t.bv?.webContents.isDestroyed()) t.bv.webContents.setUserAgent(ua); }
  }

  if ('uaRotate' in patch) {
    for (const t of tabMap.values()) {
      if (!t.bv || t.bv.webContents.isDestroyed()) continue;
      const ua = settings.uaRotate
        ? _UA_ROTATE_POOL[Math.floor(Math.random() * _UA_ROTATE_POOL.length)]
        : (settings.spoofUserAgent !== false ? SPOOF_UA : undefined);
      if (ua) t.bv.webContents.setUserAgent(ua);
    }
  }

  // Re-inject geo spoofer live when geo settings change
  if ('geoEnabled' in patch || 'geoRegion' in patch) {
    for (const t of tabMap.values()) {
      if (!t.bv || t.url === 'newtab' || t.bv.webContents.isDestroyed()) continue;
      if (settings.geoEnabled && settings.geoRegion && GEO_REGIONS[settings.geoRegion]) {
        const gr = GEO_REGIONS[settings.geoRegion];
        t.bv.webContents.executeJavaScript(buildGeoScript(gr.lat, gr.lon)).catch(() => {});
      }
    }
  }

  // Game Mode — pause/resume Discord RPC and background timers
  if ('gameMode' in patch) {
    if (patch.gameMode) {
      if (_rpcInterval) { clearInterval(_rpcInterval); _rpcInterval = null; }
      if (discordRpc) { try { discordRpc.destroy(); } catch {} discordRpc = null; }
      // Notify renderer to freeze non-essential animations/transitions
      if (win && !win.isDestroyed()) win.webContents.send('game-mode:on');
      // Throttle background tabs — suspend their rendering
      for (const [id, tab] of tabMap) {
        if (id !== activeId && tab.bv && !tab.bv.isDestroyed()) {
          try { tab.bv.webContents.setBackgroundThrottling(true); } catch {}
        }
      }
    } else {
      if (!settings.discordRpcDisabled) initDiscordRPC();
      // Notify renderer to restore animations
      if (win && !win.isDestroyed()) win.webContents.send('game-mode:off');
      // Restore background tabs
      for (const [, tab] of tabMap) {
        if (tab.bv && !tab.bv.isDestroyed()) {
          try { tab.bv.webContents.setBackgroundThrottling(false); } catch {}
        }
      }
    }
  }

  // Memory Saver — restart interval when setting changes
  if ('memorySaver' in patch) {
    _startMemSaver();
  }
  // Discord RPC enabled/disabled toggle
  if ('discordRpcDisabled' in patch) {
    if (patch.discordRpcDisabled) {
      if (_rpcInterval) { clearInterval(_rpcInterval); _rpcInterval = null; }
      if (discordRpc) { try { discordRpc.destroy(); } catch {} discordRpc = null; }
    } else if (!settings.gameMode) {
      initDiscordRPC();
    }
  }
});

// ── Memory Saver ──────────────────────────────────────────────────────────────
// Suspends inactive tabs to free RAM. Three modes:
//   off        – no automatic suspension
//   moderate   – suspend tabs inactive for > 30 min
//   aggressive – suspend tabs inactive for > 10 min
let _memSaverInterval = null;

function _getMemSaverThresholdMs() {
  const mode = settings.memorySaver || 'off';
  if (mode === 'moderate')   return 30 * 60 * 1000;
  if (mode === 'aggressive') return 10 * 60 * 1000;
  return 0;
}

function _startMemSaver() {
  if (_memSaverInterval) { clearInterval(_memSaverInterval); _memSaverInterval = null; }
  const threshold = _getMemSaverThresholdMs();
  if (!threshold) return;
  _memSaverInterval = setInterval(() => {
    if (!win || win.isDestroyed()) return;
    const now = Date.now();
    for (const [id, tab] of tabMap) {
      if (id === activeId) continue;         // never suspend active tab
      if (tab.suspended) continue;           // already suspended
      if (!tab.url || tab.url === 'newtab') continue;
      if (!tab.bv || tab.bv.webContents.isDestroyed()) continue;
      const lastActive = tab.lastActiveTime || 0;
      if (now - lastActive < threshold) continue;
      // Suspend: load blank to free renderer memory
      tab.suspended    = true;
      tab.suspendedUrl = tab.url;
      tab.snapshot     = null; // free JPEG base64 string
      try {
        const wc = tab.bv.webContents;
        wc.setBackgroundThrottling(true);
        wc.loadURL('about:blank').catch(() => {});
      } catch {}
      send('tab:update', { id, suspended: true, title: tab.title, favicon: tab.favicon, memMB: 0 });
    }
  }, 60 * 1000); // check every minute
}

// ── Tab memory metrics ────────────────────────────────────────────────────────
// Collects per-tab RAM usage via app.getAppMetrics() and sends to renderer.
let _memMetricsInterval = null;

function _startMemMetrics() {
  if (_memMetricsInterval) { clearInterval(_memMetricsInterval); _memMetricsInterval = null; }
  _memMetricsInterval = setInterval(() => {
    if (!win || win.isDestroyed()) return;
    try {
      const metrics = app.getAppMetrics();
      // Build pid → workingSetSize (KB) map
      const pidMem = {};
      for (const m of metrics) {
        if (m.pid && m.memory) pidMem[m.pid] = m.memory.workingSetSize || 0;
      }
      const tabMem = {};
      for (const [id, tab] of tabMap) {
        if (tab.bv && !tab.bv.webContents.isDestroyed()) {
          const pid = tab.bv.webContents.getOSProcessId();
          const mb  = Math.round((pidMem[pid] || 0) / 1024);
          if (tab.memMB !== mb) { tab.memMB = mb; }
          tabMem[id] = mb;
        }
      }
      send('tab:mem-update', tabMem);
    } catch {}
  }, 5000); // every 5 seconds
}

// Start both on app ready (called after win creation)

// ── IPC: Language ──────────────────────────────────────────────────────────────
function applyPreferredLanguage(lang) {
  if (!lang) return;
  try {
    const { session } = require('electron');
    session.defaultSession.webRequest.onBeforeSendHeaders({ urls: ['<all_urls>'] }, (details, cb) => {
      const h = { ...details.requestHeaders };
      h['Accept-Language'] = lang + ', en;q=0.9';
      cb({ requestHeaders: h });
    });
  } catch (e) {}
}
ipcMain.on('language:set', (_, lang) => {
  if (!lang) return;
  settings.preferredLanguage = lang;
  // Sync translateLang so auto-translate targets the same language
  const baseLang = lang.split('-')[0].toLowerCase();
  if (baseLang) settings.translateLang = baseLang;
  save(F.settings, settings);
  applyPreferredLanguage(lang);
  send('settings:set', settings);
});

// ── IPC: AI Summarize ─────────────────────────────────────────────────────────
async function _aiSummarize(text, provider, apiKey) {
  const maxTokens   = settings.aiMaxTokens   || 400;
  const temperature = settings.aiTemperature ?? 0.5;
  const customModel = settings.aiModel       || '';
  const defaultPrompt = `Summarize the following content clearly and concisely in 3-5 sentences. Be direct and informative:\n\n${text.slice(0, 6000)}`;
  const prompt = settings.aiCustomPrompt
    ? `${settings.aiCustomPrompt}\n\n${text.slice(0, 6000)}`
    : defaultPrompt;
  try {
    if (provider === 'openai' || provider === 'deepseek') {
      const url   = provider === 'openai'
        ? 'https://api.openai.com/v1/chat/completions'
        : 'https://api.deepseek.com/chat/completions';
      const model = customModel || (provider === 'openai' ? 'gpt-4o-mini' : 'deepseek-chat');
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, messages: [{ role: 'user', content: prompt }], max_tokens: maxTokens, temperature }),
      });
      const j = await res.json();
      return j.choices?.[0]?.message?.content || j.error?.message || 'No response received.';
    } else if (provider === 'claude') {
      const model = customModel || 'claude-haiku-4-5-20251001';
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, max_tokens: maxTokens, temperature, messages: [{ role: 'user', content: prompt }] }),
      });
      const j = await res.json();
      return j.content?.[0]?.text || j.error?.message || 'No response received.';
    } else if (provider === 'gemini') {
      const model = customModel || 'gemini-1.5-flash-latest';
      const res = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
        { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { maxOutputTokens: maxTokens, temperature } }) }
      );
      const j = await res.json();
      return j.candidates?.[0]?.content?.parts?.[0]?.text || j.error?.message || 'No response received.';
    }
    return 'Unknown AI provider.';
  } catch (e) {
    return `Error: ${e.message}`;
  }
}
ipcMain.on('ai:summarize', async (_, { text }) => {
  if (!settings.aiProvider || !settings.aiApiKey) {
    send('ai:result', { error: 'No AI provider configured. Add your API key in Settings → AI.' });
    return;
  }
  send('ai:result', { loading: true });
  const result = await _aiSummarize(text, settings.aiProvider, settings.aiApiKey);
  send('ai:result', { text: result });
});

// ── IPC: Zoom ─────────────────────────────────────────────────────────────────
ipcMain.on('zoom:in',    (_, id) => setZoom(id, z => Math.min(z + 0.1, 3)));
ipcMain.on('zoom:out',   (_, id) => setZoom(id, z => Math.max(z - 0.1, 0.3)));
ipcMain.on('zoom:reset', (_, id) => setZoom(id, ()  => 1));

// ── IPC: Find ─────────────────────────────────────────────────────────────────
ipcMain.on('find', (_, { id, text, forward }) => {
  const t = tabMap.get(id);
  if (!t || !text) return;
  t.bv.webContents.findInPage(text, { forward });
});
ipcMain.on('find:stop', (_, id) => {
  tabMap.get(id)?.bv.webContents.stopFindInPage('clearSelection');
});

// ── IPC: DevTools / print / view-source ──────────────────────────────────────
ipcMain.on('devtools',    (_, id) => tabMap.get(id)?.bv.webContents.toggleDevTools());
ipcMain.on('print',       (_, id) => tabMap.get(id)?.bv.webContents.print());
ipcMain.on('source:view', (_, id) => {
  const t = tabMap.get(id);
  if (t?.url && t.url !== 'newtab') createTab('view-source:' + t.url);
});

// ── IPC: Privacy / clear data ─────────────────────────────────────────────────
ipcMain.on('privacy:clear', async (_, opts = {}) => {
  const ses = session.fromPartition('persist:main');
  if (opts.cache)   await ses.clearCache();
  if (opts.cookies) {
    await ses.clearStorageData({
      storages: ['cookies','localstorage','indexdb','websql','filesystem','serviceworkers','cachestorage'],
    });
  }
  if (opts.history)   { history   = []; save(F.history,   []); send('history:set',      []); }
  if (opts.downloads) { downloads = []; save(F.downloads, []); send('downloads:update', []); }
});

// ── IPC: Whitelist ────────────────────────────────────────────────────────────
ipcMain.on('whitelist:add', (_, domain) => {
  const d = domain.toLowerCase()
    .replace(/^(https?:\/\/)?(www\.)?/, '')
    .replace(/\/.*$/, '')
    .trim();
  if (d && !userWhitelist.includes(d)) {
    userWhitelist.push(d);
    save(F.whitelist, userWhitelist);
    send('whitelist:set', userWhitelist);
  }
});
ipcMain.on('whitelist:remove', (_, domain) => {
  userWhitelist = userWhitelist.filter(d => d !== domain);
  save(F.whitelist, userWhitelist);
  send('whitelist:set', userWhitelist);
});

// Temp bypass: user clicked "Continue anyway" on blocked page
const _tempBypassSet = new Set();
ipcMain.on('whitelist:temp-add', (_, host) => {
  if (typeof host === 'string' && host) _tempBypassSet.add(host.toLowerCase());
});

// ── IPC: Wallpaper picker ─────────────────────────────────────────────────────
ipcMain.on('wallpaper:pick', async () => {
  const r = await dialog.showOpenDialog(win, {
    properties: ['openFile'],
    filters: [
      { name: 'Wallpapers', extensions: ['jpg','jpeg','png','gif','webp','mp4','webm','ogg','mov'] },
      { name: 'Images', extensions: ['jpg','jpeg','png','gif','webp'] },
      { name: 'Videos (Live Wallpaper)', extensions: ['mp4','webm','ogg','mov'] },
    ],
  });
  if (!r.canceled && r.filePaths[0]) {
    // Store as a proper file:// URL so Chromium can use it directly
    const wpUrl = pathToFileURL(r.filePaths[0]).href;
    settings.wallpaper = wpUrl;
    // Add to user wallpaper library if not already present
    if (!settings.wallpaperLibrary) settings.wallpaperLibrary = [];
    const label = require('path').basename(r.filePaths[0], require('path').extname(r.filePaths[0])).replace(/[-_]/g, ' ');
    if (!settings.wallpaperLibrary.some(w => w.url === wpUrl)) {
      settings.wallpaperLibrary.push({ url: wpUrl, label });
    }
    // Default audio on for live (video) wallpapers
    const isVideo = /\.(mp4|webm|ogg|mov)$/i.test(r.filePaths[0]);
    if (isVideo) settings.liveWallpaperAudio = true;
    save(F.settings, settings);
    send('settings:set', settings);
  }
});

// ── IPC: Plugins (custom CSS / JS injection) ──────────────────────────────────
ipcMain.handle('plugins:get', () => settings.plugins || {});
// Exposed by preload.js contextBridge for tab content — returns full settings object
ipcMain.handle('get-settings', () => settings);

ipcMain.on('plugins:set', (_, patch) => {
  if (!settings.plugins) settings.plugins = { css: '', cssEnabled: false, js: '', jsEnabled: false };
  const wasCssEnabled = settings.plugins.cssEnabled;
  settings.plugins = { ...settings.plugins, ...patch };
  save(F.settings, settings);
  send('settings:set', settings);
  // Re-inject into the currently active tab immediately
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab' && !tab.bv.webContents.isDestroyed()) {
    const wc = tab.bv.webContents;
    const pl = settings.plugins;
    // Remove previously inserted custom CSS before re-inserting (prevents duplicates)
    if (tab._pluginCSSKey) {
      wc.removeInsertedCSS(tab._pluginCSSKey).catch(() => {});
      tab._pluginCSSKey = null;
    }
    if (pl.cssEnabled && pl.css) {
      wc.insertCSS(pl.css, { cssOrigin: 'user' }).then(key => { tab._pluginCSSKey = key; }).catch(() => {});
    }
    if (pl.jsEnabled  && pl.js)  wc.executeJavaScript(pl.js).catch(() => {});
  }
});

// ── IPC: Extensions ───────────────────────────────────────────────────────────
ipcMain.on('ext:toggle', (_, { id, enabled }) => {
  if (!settings.extensions) settings.extensions = {};
  settings.extensions[id] = !!enabled;
  save(F.settings, settings);
  send('settings:set', settings); // keep renderer state in sync
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab') {
    const script = enabled ? EXT_SCRIPTS[id] : EXT_UNSCRIPTS[id];
    if (script) tab.bv.webContents.executeJavaScript(script).catch(() => {});
  } else if (tab?.url === 'newtab' && enabled) {
    // Let the user know the add-on will activate on the next page they visit
    send('toast', 'Add-on enabled — navigate to a page to activate it');
  }
  // Custom cursor: also inject/remove the ring overlay in the main browser chrome
  if (id === 'custom-cursor' && win && !win.isDestroyed()) {
    const winScript = enabled ? EXT_SCRIPTS['custom-cursor'] : EXT_UNSCRIPTS['custom-cursor'];
    if (winScript) win.webContents.executeJavaScript(winScript).catch(() => {});
  }
});

ipcMain.on('extensions:ctx-menu', () => {
  if (!win || win.isDestroyed()) return;
  const EXT_NAMES = {
    'dark-mode':      'Dark Mode',
    'grayscale':      'Grayscale',
    'night-filter':   'Night Filter',
    'no-animations':  'No Animations',
    'font-boost':     'Font Boost',
    'custom-cursor':  'Custom Cursor',
    'high-contrast':  'High Contrast',
    'neon-glow':      'Neon Glow',
    'serif-mode':     'Serif Mode',
    'yt-ad':          'YouTube Ad Skip',
    'focus-mode':     'Focus Mode',
    'reader-mode':    'Reader Mode',
    'bug-cursor':     'Bug Cursor',
  };
  const exts = settings.extensions || {};
  const items = [
    { label: 'Add-ons & Themes', enabled: false },
    { type: 'separator' },
    ...Object.entries(EXT_NAMES).map(([id, name]) => ({
      label: name,
      type: 'checkbox',
      checked: !!exts[id],
      click: () => {
        const nowEnabled = !exts[id];
        if (!settings.extensions) settings.extensions = {};
        settings.extensions[id] = nowEnabled;
        save(F.settings, settings);
        send('settings:set', settings);
        send('ext:toggle', id);  // tell renderer to sync checkbox
        // Inject/remove script on active tab
        const tab = tabMap.get(activeId);
        if (tab?.bv && tab.url !== 'newtab') {
          const script = nowEnabled ? EXT_SCRIPTS[id] : EXT_UNSCRIPTS[id];
          if (script) tab.bv.webContents.executeJavaScript(script).catch(() => {});
        }
        if (id === 'custom-cursor' && win && !win.isDestroyed()) {
          const ws = nowEnabled ? EXT_SCRIPTS['custom-cursor'] : EXT_UNSCRIPTS['custom-cursor'];
          if (ws) win.webContents.executeJavaScript(ws).catch(() => {});
        }
        if (id === 'bug-cursor') {
          win.webContents.executeJavaScript(`if(window._bugCursorSetEnabled) window._bugCursorSetEnabled(${nowEnabled})`).catch(() => {});
        }
      }
    })),
    { type: 'separator' },
    { label: 'Open Add-ons Manager', click: () => send('ext:open-store') },
  ];
  Menu.buildFromTemplate(items).popup({ window: win });
});

// ── IPC: Incognito separate window ────────────────────────────
let incognitoWin  = null;
const igTabMap    = new Map();
let   igNextId    = 5000;
let   igActiveId  = null;

function sendIg(ch, ...a) {
  if (incognitoWin && !incognitoWin.isDestroyed()) incognitoWin.webContents.send(ch, ...a);
}

const IG_TOP = 82; // tab-row 34 + nav-row 48
const IG_SEARCH = 'https://www.startpage.com/search?q=';
function igResolveUrl(raw) {
  if (!raw || raw === 'newtab') return 'newtab';
  // Allow file:// URLs and bare paths pointing to local html/xhtml/pdf files
  if (/\.(html?|xhtml|pdf)$/i.test(raw) && !/^(javascript|vbscript|data):/i.test(raw)) return raw;
  if (/^(javascript|vbscript|data|file):/i.test(raw)) return IG_SEARCH + encodeURIComponent(raw);
  if (/^(https?|ftp):\/\//i.test(raw)) return raw;
  if (/^(about:|view-source:)/i.test(raw)) return raw;
  if (/^localhost(:\d+)?(\/.*)?$/.test(raw)) return 'http://' + raw;
  if (/^[\w-]+(\.[\w-]+)+(\/.*)?$/.test(raw)) return 'https://' + raw;
  return IG_SEARCH + encodeURIComponent(raw);
}
function igSetBounds(bv) {
  if (!incognitoWin || incognitoWin.isDestroyed()) return;
  const [w, h] = incognitoWin.getContentSize();
  bv.setBounds({ x: 0, y: IG_TOP, width: w, height: Math.max(1, h - IG_TOP) });
}

function igNavData(tab) {
  if (!tab?.bv || tab.bv.webContents.isDestroyed()) return { url: tab?.url, canBack: false, canFwd: false };
  const wc = tab.bv.webContents;
  return { url: tab.url, title: tab.title, loading: tab.loading, canBack: wc.navigationHistory?.canGoBack() ?? wc.canGoBack(), canFwd: wc.navigationHistory?.canGoForward() ?? wc.canGoForward() };
}

function igActivateTab(id) {
  const tab = igTabMap.get(id);
  if (!tab || !incognitoWin || incognitoWin.isDestroyed()) return;
  for (const t of igTabMap.values()) { if (t.bv) try { incognitoWin.removeBrowserView(t.bv); } catch {} }
  if (tab.bv && tab.url !== 'newtab' && !tab.bv.webContents.isDestroyed()) {
    igSetBounds(tab.bv);
    incognitoWin.addBrowserView(tab.bv);
  }
  igActiveId = id;
  sendIg('ig:tab:activate', id);
  sendIg('ig:nav:state', igNavData(tab));
}

function igCreateTab(url = 'newtab', activate = true) {
  const id = ++igNextId;
  const bv = new BrowserView({
    backgroundColor: '#0a071a',
    webPreferences: {
      nodeIntegration:  false,
      contextIsolation: true,
      sandbox:          true,
      partition:        'incognito',
      preload:          path.join(__dirname, 'preload.js'),
      webSecurity:      true,
      experimentalFeatures: true,
    },
  });
  const tab = { id, bv, url: url === 'newtab' ? 'newtab' : url, title: 'New Tab', favicon: null, loading: false };
  igTabMap.set(id, tab);
  const wc = bv.webContents;
  wc.setBackgroundThrottling(false);
  wc.setUserAgent(SPOOF_UA);
  wc.setWindowOpenHandler(({ url: u }) => {
    if (/^(javascript|vbscript|file):/i.test(u)) return { action: 'deny' };
    igCreateTab(u, true); return { action: 'deny' };
  });
  // Inject Google UA fix on every page load in incognito (email → password → 2FA)
  wc.on('dom-ready', () => _injectGoogleUAFix(wc));
  const norm = u => (u && u !== 'about:blank') ? u : '';
  wc.on('page-title-updated', (_, t) => {
    tab.title = t;
    sendIg('ig:tab:update', { id, url: tab.url, title: t, loading: tab.loading, favicon: tab.favicon });
    if (igActiveId === id) sendIg('ig:nav:state', igNavData(tab));
  });
  wc.on('did-start-loading', () => {
    tab.loading = true;
    sendIg('ig:tab:update', { id, url: tab.url, title: tab.title, loading: true, favicon: tab.favicon });
  });
  wc.on('did-navigate', (_, u) => {
    tab.url = norm(u) || tab.url; tab.favicon = null;
    sendIg('ig:tab:update', { id, url: tab.url, title: tab.title, loading: tab.loading, favicon: null });
    if (igActiveId === id) sendIg('ig:nav:state', igNavData(tab));
    _injectGoogleUAFix(wc);
  });
  wc.on('did-navigate-in-page', (_, u) => {
    tab.url = norm(u) || tab.url;
    sendIg('ig:tab:update', { id, url: tab.url, title: tab.title, loading: tab.loading, favicon: tab.favicon });
    if (igActiveId === id) sendIg('ig:nav:state', igNavData(tab));
    _injectGoogleUAFix(wc);
  });
  wc.on('page-favicon-updated', (_, favs) => {
    tab.favicon = favs[0] || null;
    sendIg('ig:tab:update', { id, url: tab.url, title: tab.title, loading: tab.loading, favicon: tab.favicon });
  });
  wc.on('did-stop-loading', () => {
    tab.loading = false;
    tab.url = norm(wc.getURL()) || tab.url;
    sendIg('ig:tab:update', { id, url: tab.url, title: tab.title, loading: false, favicon: tab.favicon });
    if (igActiveId === id) sendIg('ig:nav:state', igNavData(tab));
    if (/youtube\.com/i.test(tab.url) && settings.extensions?.['yt-ad'] && !/\/shorts\//i.test(tab.url)) wc.executeJavaScript(YT_AD_SKIP).catch(() => {});
    if (!/tiktok\.com/i.test(tab.url || '')) {
      wc.insertCSS('html{overflow-y:overlay!important;scrollbar-width:thin!important}html::-webkit-scrollbar{width:6px!important;height:6px!important;background:transparent!important}html::-webkit-scrollbar-thumb{background:rgba(128,128,128,.3)!important;border-radius:3px!important}html::-webkit-scrollbar-track{background:transparent!important}', { cssOrigin:'user' }).catch(() => {});
    }
    // Inject floating PiP button — same as main browser
    if (tab.url && tab.url !== 'newtab' && !tab.url.startsWith('view-source:')) {
      wc.executeJavaScript('window._rawPipInjected=false;window._rawPipV3=false;').catch(()=>{});
      wc.executeJavaScript(VIDEO_PIP_INJECT).catch(() => {});
    }
  });
  sendIg('ig:tab:add', { id, url: tab.url, title: tab.title, loading: false, favicon: null });
  if (url !== 'newtab') {
    const resolved = igResolveUrl(url);
    tab.url = resolved; tab.loading = true;
    wc.loadURL(resolved).catch(() => {});
  }
  if (activate) igActivateTab(id);
  return tab;
}

ipcMain.on('incognito:open', () => {
  if (incognitoWin && !incognitoWin.isDestroyed()) { incognitoWin.focus(); return; }
  const _igMacOpts = process.platform === 'darwin' ? {
    titleBarStyle: 'hidden',
    trafficLightPosition: { x: 12, y: 8 },
  } : { frame: false };
  incognitoWin = new BrowserWindow({
    width: 1200, height: 800, minWidth: 640, minHeight: 400,
    ..._igMacOpts, transparent: true, backgroundColor: '#00000000',
    icon: path.join(__dirname, 'assets',
      process.platform === 'darwin' ? 'logo.icns' :
      process.platform === 'linux'  ? 'logo.png'  : 'logo.ico'),
    webPreferences: { nodeIntegration: true, contextIsolation: false, webviewTag: false },
  });
  igTabMap.clear(); igActiveId = null; igNextId = 5000;
  incognitoWin.loadFile(path.join(__dirname, 'incognito.html'));
  incognitoWin.once('ready-to-show', () => {
    incognitoWin.show();
    if (win && !win.isDestroyed()) win.webContents.send('incognito:state', true);
    // Send current theme/accent so incognito window can match
    sendIg('ig:settings', { theme: settings.theme || 'midnight', accentColor: settings.accentColor });
    // Also broadcast full theme CSS variable set so incognito matches the current palette exactly
    setTimeout(() => _broadcastThemeToPopups(), 80);
    igCreateTab('newtab', true);
  });
  incognitoWin.on('resize', () => {
    for (const t of igTabMap.values()) {
      if (t.bv && t.url !== 'newtab' && !t.bv.webContents.isDestroyed()) try { igSetBounds(t.bv); } catch {}
    }
  });
  incognitoWin.on('closed', () => {
    for (const t of igTabMap.values()) { if (t.bv) try { const wc = t.bv.webContents; if (wc && !wc.isDestroyed()) { wc.removeAllListeners(); wc.destroy(); } } catch {} }
    igTabMap.clear(); igActiveId = null; incognitoWin = null;
    if (win && !win.isDestroyed()) win.webContents.send('incognito:state', false);
  });
});

ipcMain.on('ig:tab:create',   (_, url) => igCreateTab(url || 'newtab', true));
ipcMain.on('ig:tab:activate', (_, id)  => igActivateTab(id));
ipcMain.on('ig:tab:close',    (_, id)  => {
  const tab = igTabMap.get(id); if (!tab) return;
  if (tab.bv) { try { incognitoWin?.removeBrowserView(tab.bv); } catch {} try { const wc = tab.bv.webContents; if (wc && !wc.isDestroyed()) { wc.removeAllListeners(); wc.destroy(); } } catch {} }
  igTabMap.delete(id);
  if (igTabMap.size === 0) { if (incognitoWin && !incognitoWin.isDestroyed()) incognitoWin.close(); return; }
  if (igActiveId === id) { const next = [...igTabMap.values()].pop(); if (next) igActivateTab(next.id); }
  sendIg('ig:tab:remove', id);
});
ipcMain.on('ig:tab:contextmenu', (event, { tabId, pinned }) => {
  const { Menu } = require('electron');
  const wc = event.sender;
  const menu = Menu.buildFromTemplate([
    {
      label: pinned ? 'Unpin Tab' : 'Pin Tab',
      click: () => { if (!wc.isDestroyed()) wc.send('ig:tab:set-pin', { tabId, pinned: !pinned }); }
    },
    { type: 'separator' },
    {
      label: 'Close Tab',
      click: () => { if (!wc.isDestroyed()) wc.send('ig:close-tab-native', tabId); }
    }
  ]);
  menu.popup({ window: BrowserWindow.fromWebContents(wc) });
});
ipcMain.on('ig:nav:go', (_, raw) => {
  const tab = igTabMap.get(igActiveId); if (!tab?.bv) return;
  const url = igResolveUrl(raw); tab.url = url; tab.loading = true;
  // Ensure BrowserView is visible (won't be attached if we were on newtab)
  if (incognitoWin && !incognitoWin.isDestroyed()) {
    try { incognitoWin.removeBrowserView(tab.bv); } catch {}
    incognitoWin.addBrowserView(tab.bv);
    igSetBounds(tab.bv);
  }
  tab.bv.webContents.loadURL(url).catch(() => {});
});
ipcMain.on('ig:nav:back',    () => { const t = igTabMap.get(igActiveId); if (t?.bv) t.bv.webContents.goBack(); });
ipcMain.on('ig:nav:forward', () => { const t = igTabMap.get(igActiveId); if (t?.bv) t.bv.webContents.goForward(); });
ipcMain.on('ig:nav:reload',  () => { const t = igTabMap.get(igActiveId); if (t?.bv) t.bv.webContents.reload(); });
ipcMain.on('ig:nav:stop',    () => { const t = igTabMap.get(igActiveId); if (t?.bv) t.bv.webContents.stop(); });
ipcMain.on('ig:win:minimize', () => { incognitoWin?.minimize(); });
ipcMain.on('ig:win:maximize', () => {
  if (!incognitoWin) return;
  incognitoWin.isMaximized() ? incognitoWin.unmaximize() : incognitoWin.maximize();
});
ipcMain.on('ig:win:close',   () => { incognitoWin?.close(); });
ipcMain.on('ig:win:moveBy',  (_, { dx, dy }) => {
  if (!incognitoWin || incognitoWin.isDestroyed()) return;
  const [x, y] = incognitoWin.getPosition();
  incognitoWin.setPosition(Math.round(x + dx), Math.round(y + dy));
});

ipcMain.on('ig:pip:start', () => {
  const tab = igTabMap.get(igActiveId);
  if (!tab?.bv) { sendIg('ig:toast', 'No active tab'); return; }
  tab.bv.webContents.executeJavaScript(`
    (function(){
      var v=document.querySelector('video');
      if(!v){return 'no-video';}
      if(document.pictureInPictureElement){document.exitPictureInPicture().catch(function(){});}
      else{v.requestPictureInPicture().catch(function(e){console.warn('[RAW Incognito] PiP:',e.message);});}
    })()
  `).catch(() => {});
});

// ── IPC: Main-browser PiP — same method as incognito, userGesture propagated from toolbar click ──
ipcMain.on('bv:pip:start', () => {
  const tab = tabMap.get(activeId);
  if (!tab?.bv) return;
  tab.bv.webContents.executeJavaScript(`
    (function(){
      // If PiP already active, toggle off and return
      if(document.pictureInPictureElement){
        document.exitPictureInPicture().catch(function(){});
        return;
      }
      var vw=window.innerWidth, vh=window.innerHeight;
      var cy=vh/2; // viewport centre Y
      var best=null, bestScore=-1;
      var isTikTok=/tiktok\.com/i.test(location.hostname);
      document.querySelectorAll('video').forEach(function(v){
        var r=v.getBoundingClientRect();
        if(r.width<80||r.height<50)return;
        if(r.right<0||r.bottom<0||r.left>vw||r.top>vh)return;
        // On TikTok, heavily prefer whichever video centre is nearest viewport centre
        // to avoid picking the pre-buffered video above/below the current one.
        var distFromCentre=Math.abs((r.top+r.height/2)-cy);
        var score=(!v.paused?3000:0)+(v.duration||0)*10+(r.width*r.height/1e4);
        if(isTikTok) score-=distFromCentre*20;
        if(score>bestScore){bestScore=score;best=v;}
      });
      // YouTube fallback
      if(!best) best=document.querySelector('#movie_player video,.html5-video-player video');
      // Generic fallback
      if(!best) best=document.querySelector('video');
      if(!best)return;
      try{best.disablePictureInPicture=false;}catch(e){}
      best.requestPictureInPicture().catch(function(e){
        console.warn('[RAW PiP]',e.message);
      });
    })()
  `, true /* userGesture — propagated from toolbar button click via IPC */).catch(() => {});
});

// ── IPC: Autofill bridge ──────────────────────────────────────────────────────
ipcMain.on('autofill:query', (_, data) => {
  // Forward login-form detection from active tab to renderer (vault lookup)
  send('autofill:query', data);
});
ipcMain.on('autofill:fill', (_, data) => {
  // Forward fill credentials back to the active tab's preload
  const tab = tabMap.get(activeId);
  if (tab && tab.bv) tab.bv.webContents.send('autofill:fill', data);
});
ipcMain.on('autofill:save-prompt', (_, data) => {
  // Forward save-password prompt from active tab to renderer
  send('autofill:save-prompt', data);
});

// ── IPC: Picture-in-Picture ───────────────────────────────────────────────────
ipcMain.on('pip:start', () => {
  const tab = tabMap.get(activeId);
  if (!tab?.bv) { send('toast', 'No active tab', 'err'); return; }
  tab.bv.webContents.executeJavaScript(`
    (function(){
      var v=document.querySelector('video');
      if(!v){return 'no-video';}
      if(document.pictureInPictureElement){document.exitPictureInPicture().catch(function(){});}
      else{v.requestPictureInPicture().catch(function(e){console.warn('[RAW] PiP:',e.message);});}
    })()
  `).then(res => {
    if (res === 'no-video') send('toast', 'No video found on this page', 'err');
  }).catch(() => {});
});

// ── Translate URL builder — uses translate.google.com wrapper ────────────────
function _toTranslateUrl(pageUrl, targetLang) {
  // Use translate.google.com/translate wrapper — more reliable than *.translate.goog
  // in Electron since the proxy doesn't require pre-existing Google cookies.
  return `https://translate.google.com/translate?sl=auto&tl=${encodeURIComponent(targetLang)}&u=${encodeURIComponent(pageUrl)}`;
}

// ── IPC: Translate ────────────────────────────────────────────────────────────
ipcMain.on('translate:page', (_, { lang, newTab } = {}) => {
  const tab = tabMap.get(activeId);
  if (!tab || tab.url === 'newtab') return;
  const targetLang = lang || settings.translateLang || 'en';
  const url = _toTranslateUrl(tab.url, targetLang);
  if (newTab) {
    createTab(url, true);
  } else {
    tab.bv?.webContents.loadURL(url);
  }
});

// ── IPC: Misc ─────────────────────────────────────────────────────────────────
ipcMain.on('adblock:refresh', async () => {
  send('toast', 'Downloading filter lists…', 'teal');
  try {
    const count = await _loadFilterLists(true);
    send('toast', `Filter lists updated — ${count.toLocaleString()} rules loaded`, 'teal');
  } catch {
    send('toast', 'Could not refresh filter lists — using cached copy', 'amber');
  }
});
ipcMain.handle('adblock:status', () => ({
  rulesCount: _filterRulesCount,
  sources: FILTER_SOURCES.map(s => {
    const p = require('path').join(app.getPath('userData'), 'landerbrowser', 'filters', s.name + '.txt');
    return {
      name: s.name,
      cached: fs.existsSync(p),
      age: fs.existsSync(p) ? Math.round((Date.now() - fs.statSync(p).mtimeMs) / 3600000) : null,
    };
  }),
}));
// poison:signal — updates the session's webRequest extraHeaders with persona interests
// so outgoing ad-network requests carry spoofed interest signals via HTTP headers.
// These headers are ignored by most first-party sites but read by some DSPs.
ipcMain.on('poison:signal', (_e, { keyword, interests } = {}) => {
  try {
    const kw   = String(keyword  || '').slice(0, 80).replace(/[^\w\s-]/g, '');
    const ints = (Array.isArray(interests) ? interests : []).slice(0, 8)
                   .map(s => String(s).slice(0, 30).replace(/[^\w\s-]/g, '')).join(', ');
    if (!kw) return;
    // Store as session-level header override for ad network requests
    // Uses non-standard headers that DSPs sometimes read, harmless to first-party sites
    const ses = win?.webContents?.session;
    if (!ses) return;
    ses.webRequest.onBeforeSendHeaders({ urls: ['*://securepubads.g.doubleclick.net/*', '*://pagead2.googlesyndication.com/*', '*://ads.twitter.com/*', '*://connect.facebook.net/*', '*://pixel.advertising.com/*'] },
      (details, cb) => {
        cb({ requestHeaders: { ...details.requestHeaders, 'X-Interest-Category': kw, 'X-Audience-Segment': ints || kw } });
      }
    );
  } catch {}
});

ipcMain.on('filter-lists:set', async (_, state) => {
  if (state && typeof state === 'object') {
    _enabledFilterLists = { ...{ easylist: true, easyprivacy: true, annoyances: true, social: false, malware: false }, ...state };
    try {
      await _loadFilterLists(false);
    } catch {}
  }
});

// Inject persona-appropriate cookies & localStorage into the active tab (safe — only affects current page domain)
ipcMain.on('poison:inject-cookies', (_e, { keyword, interests }) => {
  const tab = tabMap.get(activeId);
  if (!tab?.bv) return;
  const kw  = String(keyword  || '').replace(/[`\\]/g, '');
  const ints = (Array.isArray(interests) ? interests : []).map(s => String(s).replace(/[`\\]/g, '')).slice(0, 20);
  // Inject safely — only sets cookies/localStorage for the current page's own domain
  tab.bv.webContents.executeJavaScript(`
    (function(kw, ints) {
      try {
        localStorage.setItem('_raw_persona',     kw);
        localStorage.setItem('_raw_interests',   ints.join(','));
        localStorage.setItem('_ga_audience_seg', kw);
        localStorage.setItem('_fbp_interests',   ints.join('|'));
      } catch {}
      try {
        const d = new Date(); d.setFullYear(d.getFullYear() + 1);
        const exp = '; path=/; expires=' + d.toUTCString();
        document.cookie = '_persona='          + encodeURIComponent(kw)             + exp;
        document.cookie = 'audience_segment='  + ints.map(encodeURIComponent).join(',') + exp;
        document.cookie = 'interest_category=' + encodeURIComponent(ints[0] || kw)  + exp;
      } catch {}
    })(${JSON.stringify(kw)}, ${JSON.stringify(ints)})
  `).catch(() => {});
});

// ── yt-dlp integration ────────────────────────────────────────────────────────
const YTDLP_REPO   = 'yt-dlp/yt-dlp';
const YTDLP_GH_API = 'https://api.github.com/repos/' + YTDLP_REPO + '/releases/latest';

function ytdlpBinName() {
  if (process.platform === 'win32') return 'yt-dlp.exe';
  if (process.platform === 'darwin') return 'yt-dlp_macos';
  return 'yt-dlp';
}

function ytdlpBinPath() {
  return path.join(app.getPath('userData'), 'landerbrowser', ytdlpBinName());
}

function ytdlpVersionFile() {
  return path.join(app.getPath('userData'), 'landerbrowser', 'yt-dlp-version.txt');
}

function ytdlpReadLocalVersion() {
  try { return fs.readFileSync(ytdlpVersionFile(), 'utf8').trim(); } catch { return null; }
}

function ytdlpSaveLocalVersion(v) {
  try { fs.writeFileSync(ytdlpVersionFile(), v); } catch {}
}

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    const opts = new URL(url);
    const req = https.get({
      hostname: opts.hostname, path: opts.pathname + opts.search,
      headers: { 'User-Agent': 'LanderBrowser/1.0', 'Accept': 'application/vnd.github+json' },
    }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return httpsGet(res.headers.location).then(resolve).catch(reject);
      }
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function httpsDownload(url, destPath) {
  return new Promise((resolve, reject) => {
    function follow(u) {
      const opts = new URL(u);
      https.get({
        hostname: opts.hostname, path: opts.pathname + opts.search,
        headers: { 'User-Agent': 'LanderBrowser/1.0' },
      }, res => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return follow(res.headers.location);
        }
        if (res.statusCode !== 200) return reject(new Error('HTTP ' + res.statusCode));
        const out = fs.createWriteStream(destPath);
        res.pipe(out);
        out.on('finish', () => { out.close(); resolve(); });
        out.on('error', reject);
      }).on('error', reject);
    }
    follow(url);
  });
}

async function ytdlpFetchLatest() {
  const { body } = await httpsGet(YTDLP_GH_API);
  const data = JSON.parse(body);
  const version = data.tag_name;
  const assetName = ytdlpBinName();
  const asset = (data.assets || []).find(a => a.name === assetName);
  if (!asset) throw new Error('No binary for this platform in latest release');
  return { version, downloadUrl: asset.browser_download_url };
}

async function ytdlpInstallOrUpdate(forceUpdate = false) {
  send('ytdlp:installing', forceUpdate ? 'Updating yt-dlp…' : 'Downloading yt-dlp…');
  try {
    const { version, downloadUrl } = await ytdlpFetchLatest();
    await httpsDownload(downloadUrl, ytdlpBinPath());
    // Make executable on unix
    if (process.platform !== 'win32') {
      try { fs.chmodSync(ytdlpBinPath(), 0o755); } catch {}
    }
    ytdlpSaveLocalVersion(version);
    send('ytdlp:status', { ready: true, version, updateAvailable: false });
  } catch (err) {
    send('ytdlp:status', { ready: false, error: 'Install failed: ' + err.message });
  }
}

async function ytdlpCheckUpdate() {
  const binExists = fs.existsSync(ytdlpBinPath());
  if (!binExists) {
    send('ytdlp:status', { ready: false, version: null, updateAvailable: true });
    return;
  }
  try {
    const local = ytdlpReadLocalVersion();
    const { version: latest } = await ytdlpFetchLatest();
    const updateAvailable = local !== latest;
    send('ytdlp:status', {
      ready: true, version: local || 'unknown',
      updateAvailable, latestVersion: latest,
    });
  } catch {
    // Network error — still mark as ready if binary exists
    const local = ytdlpReadLocalVersion();
    send('ytdlp:status', { ready: true, version: local || 'unknown', updateAvailable: false });
  }
}

// Active yt-dlp child processes keyed by job ID
const ytdlpProcs = new Map();

ipcMain.on('ytdlp:check-update', () => ytdlpCheckUpdate());
ipcMain.on('ytdlp:update',       () => ytdlpInstallOrUpdate(true));

ipcMain.handle('ytdlp:pick-outdir', async () => {
  const r = await dialog.showOpenDialog(win, { properties: ['openDirectory'] });
  return r.canceled ? null : r.filePaths[0];
});

ipcMain.on('ytdlp:download', (_, { id, url, mode, quality, audiofmt, videofmt, outdir }) => {
  const bin = ytdlpBinPath();
  if (!fs.existsSync(bin)) {
    send('ytdlp:error', { id, error: 'yt-dlp not installed' });
    ytdlpInstallOrUpdate(false);
    return;
  }

  const outDir  = outdir || app.getPath('downloads');
  // %(title).200B truncates titles to 200 bytes — avoids PATH_TOO_LONG on Windows
  const outTmpl = path.join(outDir, '%(title).200B.%(ext)s');
  let args;
  // --windows-filenames: replace chars illegal on Windows (/, \, :, *, ?, ", <, >, |)
  // --no-playlist: only download the single video, not the entire playlist
  // --newline + --progress: machine-readable progress on each line
  const baseArgs = [
    '--no-playlist', '--newline', '--progress',
    '--windows-filenames',
    '-o', outTmpl,
  ];
  if (mode === 'audio') {
    const fmt = audiofmt || 'mp3';
    // All audio formats go through -x (extract audio); ffmpeg handles conversion
    args = [url, '-x', '--audio-format', fmt, '--audio-quality', '0', ...baseArgs];
  } else {
    // Prefer a direct best mp4/webm when possible to avoid needing ffmpeg merge.
    // bestvideo[ext=mp4]+bestaudio[ext=m4a]/bestvideo+bestaudio/best avoids
    // "ffmpeg not found" errors on machines without ffmpeg installed.
    const ext    = videofmt || 'mp4';
    const fmtStr = quality ||
      (ext === 'mp4' ? 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/bestvideo+bestaudio/best'
                     : 'bestvideo+bestaudio/best');
    args = [url, '-f', fmtStr, '--merge-output-format', ext, ...baseArgs];
  }

  let outPath = '';
  let title   = '';

  const proc = spawn(bin, args, { windowsHide: true });
  ytdlpProcs.set(id, proc);

  // Collect meaningful stderr lines for error reporting
  const errLines = [];

  const lineBuffer = (stream, isStderr) => {
    let buf = '';
    stream.on('data', chunk => {
      buf += chunk.toString();
      let idx;
      while ((idx = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;

        // Collect stderr lines (skip download progress noise)
        if (isStderr && !line.startsWith('[download]') && !line.startsWith('WARNING')) {
          errLines.push(line);
        }

        // [download] Destination: /path/to/file.mp4
        const titleM = line.match(/\[download\] Destination: (.+)/);
        if (titleM) {
          const p = titleM[1].trim();
          // Ignore .part temp files for outPath display, but use them for title
          if (!p.endsWith('.part')) outPath = p;
          title = path.basename(p.replace(/\.part$/, ''), path.extname(p.replace(/\.part$/, '')));
        }

        // [ExtractAudio] Destination: final audio file
        const audioM = line.match(/\[ExtractAudio\] Destination: (.+)/);
        if (audioM) {
          outPath = audioM[1].trim();
          title   = path.basename(outPath, path.extname(outPath));
          send('ytdlp:progress', { id, percent: 99, speed: '', status: 'Converting…', title, outPath });
          continue;
        }

        // [Merger] Merging formats into "final.mp4"
        const mergeM = line.match(/\[Merger\] Merging formats into "(.+)"/);
        if (mergeM) {
          outPath = mergeM[1].trim();
          title   = path.basename(outPath, path.extname(outPath));
          send('ytdlp:progress', { id, percent: 98, speed: '', status: 'Merging…', title, outPath });
          continue;
        }

        // [MoveFiles] Moving: source → dest (after post-processing)
        const moveM = line.match(/\[MoveFiles\] Moving file from "(.+)" to "(.+)"/);
        if (moveM) {
          outPath = moveM[2].trim();
          title   = path.basename(outPath, path.extname(outPath));
          continue;
        }

        // Progress: [download]  42.3% of ~  10.00MiB at  1.23MiB/s ETA 00:04
        const prgM = line.match(/\[download\]\s+([\d.]+)%.*?at\s+([\d.]+\S*)\s+ETA\s+(\S+)/);
        if (prgM) {
          send('ytdlp:progress', {
            id, percent: parseFloat(prgM[1]),
            speed: prgM[2] + '/s', status: 'ETA ' + prgM[3],
            title, outPath,
          });
          continue;
        }

        // Fallback: any [download] line with just a percentage
        const pctM = line.match(/\[download\]\s+([\d.]+)%/);
        if (pctM) {
          send('ytdlp:progress', { id, percent: parseFloat(pctM[1]), speed: '', status: pctM[1] + '%', title, outPath });
        }
      }
    });
  };

  lineBuffer(proc.stdout, false);
  lineBuffer(proc.stderr, true);

  proc.on('close', code => {
    ytdlpProcs.delete(id);
    if (code === 0) {
      send('ytdlp:done', { id, outPath, title });
    } else if (code !== null) {
      // Make ffmpeg-missing errors user-friendly
      const raw = errLines.slice(-3).join(' ');
      let errMsg = errLines[errLines.length - 1] || ('Process exited with code ' + code);
      if (/ffmpeg/i.test(raw) && /not found|no such|install/i.test(raw)) {
        errMsg = 'ffmpeg is required for this format but was not found. Install ffmpeg or choose a different format.';
      } else if (/unsupported url/i.test(raw) || /no video formats/i.test(raw)) {
        errMsg = 'URL not supported — try a direct video page URL.';
      } else if (/sign in|login required|private video/i.test(raw)) {
        errMsg = 'This video requires sign-in and cannot be downloaded.';
      }
      send('ytdlp:error', { id, error: errMsg });
    }
  });
  proc.on('error', err => {
    ytdlpProcs.delete(id);
    send('ytdlp:error', { id, error: err.message });
  });
});

ipcMain.on('ytdlp:cancel', (_, id) => {
  const proc = ytdlpProcs.get(id);
  if (proc) { proc.kill(); ytdlpProcs.delete(id); }
});

// Update checker removed
