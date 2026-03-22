'use strict';

const { contextBridge, ipcRenderer } = require('electron');

const _SPOOF_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36';

// Apply privacy protections before any page script runs
(function hardenPrivacy() {
  try {
    const _hn = (window.location.hostname || '').toLowerCase().replace(/^www\./, '');

    // Sites that need full browser capabilities — skip heavy fingerprinting
    const _bypass = [
      // Google — all sign-in, auth, and service domains MUST be here or Google
      // detects the empty plugins/permissions fingerprint and blocks login.
      'google.com', 'googleapis.com', 'googleusercontent.com',
      'gstatic.com', 'gmail.com', 'accounts.google.com',
      'translate.google.com', // For translation feature
      // Media / streaming sites that need all Chrome APIs
      'tiktok.com', 'tiktokv.com', 'tiktokcdn.com', 'musical.ly',
      'spotify.com', '*.spotify.com',
      'scdn.co', '*.scdn.co',
      'spotifycdn.com', '*.spotifycdn.com',
      'spotifycdn.net', '*.spotifycdn.net',
      'accounts.spotify.com', 'api.spotify.com', 'spclient.wg.spotify.com',
      'apresolve.spotify.com', 'dealer.spotify.com',
      'open.spotify.com', 'www.spotify.com', 'play.spotify.com',
      'login.spotify.com', 'auth.spotify.com',
      'soundcloud.com',
      'netflix.com', 'hulu.com', 'disneyplus.com', 'primevideo.com',
      'youtube.com', 'youtu.be',
      // Microsoft / Apple sign-in flows
      'microsoft.com', 'live.com', 'microsoftonline.com',
      'apple.com', 'appleid.apple.com',
      // Facebook / Instagram sign-in
      'facebook.com', 'instagram.com', 'fbcdn.net',
    ];
    const _isBypass = !_hn || _hn === 'blank' || _bypass.some(h => {
      if (h.startsWith('*.')) {
        const domain = h.slice(2);
        return _hn === domain || _hn.endsWith('.' + domain);
      }
      return _hn === h || _hn.endsWith('.' + h);
    });

    // ── WebRTC IP leak protection — skip for media/streaming sites ──────────
    // Chromium-level protection is set via commandLine switches in main.js.
    // This JS layer adds defence-in-depth for non-bypass sites only.
    if (!_isBypass) {
      try {
        if (window.RTCPeerConnection) {
          const _OrigRTC = window.RTCPeerConnection;
          function _SafeRTC(config, constraints) {
            const safe = config ? { ...config, iceTransportPolicy: 'relay' }
                                 : { iceTransportPolicy: 'relay' };
            return new _OrigRTC(safe, constraints);
          }
          _SafeRTC.prototype = _OrigRTC.prototype;
          Object.defineProperty(window, 'RTCPeerConnection',
            { value: _SafeRTC, writable: false, configurable: false });
          if ('webkitRTCPeerConnection' in window)
            Object.defineProperty(window, 'webkitRTCPeerConnection',
              { value: _SafeRTC, writable: false, configurable: false });
        }
      } catch {}
    }

    if (_isBypass) {
      // IMPORTANT: With contextIsolation: true, Object.defineProperty in preload
      // only modifies the ISOLATED world — page scripts (Google's auth JS) run in
      // the MAIN world and still see real Electron values. We must inject a <script>
      // element so the code executes inside the page's main world, exactly like
      // injectMediaGuard does below. This is the only way to spoof navigator
      // properties so Google's login detectors actually see the spoofed values.
      //
      // KEY: This script includes Function.prototype.toString wrapping so Google
      // cannot detect that our getters are custom (non-native). Without this,
      // Google calls fn.toString() on navigator property getters and checks for
      // "[native code]" — any custom getter would be exposed as non-native.
      try {
        var _bypassCode = '(function(){' +
          'if(window._rbBypassDone)return;window._rbBypassDone=true;' +
          /* Step 0: Function.prototype.toString stealth */
          'var _fn=new WeakSet();' +
          'var _origTS=Function.prototype.toString;' +
          'var _tsProxy=function toString(){if(_fn.has(this))return"function "+(this.name||"")+"() { [native code] }";return _origTS.call(this);};' +
          '_fn.add(_tsProxy);Function.prototype.toString=_tsProxy;' +
          /* Step 0b: Object.getOwnPropertyDescriptor stealth */
          'var _origGOPD=Object.getOwnPropertyDescriptor;' +
          'var _sp=new Map();' +
          'Object.getOwnPropertyDescriptor=function(o,p){var s=_sp.get(o);if(s&&s.has(p)){var d=_origGOPD.call(Object,Object.getPrototypeOf(o)||o,p);if(d)return d;}return _origGOPD.call(Object,o,p);};' +
          '_fn.add(Object.getOwnPropertyDescriptor);' +
          /* Core spoofing functions */
          'var _UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";' +
          'function _def(t,p,v){try{var g=function(){return v;};_fn.add(g);Object.defineProperty(t,p,{get:g,configurable:true});if(!_sp.has(t))_sp.set(t,new Set());_sp.get(t).add(p);}catch(e){}}' +
          '_def(navigator,"webdriver",false);' +
          '_def(navigator,"userAgent",_UA);' +
          '_def(navigator,"vendor","Google Inc.");' +
          '_def(navigator,"platform","Win32");' +
          '_def(navigator,"language","en-US");' +
          '_def(navigator,"languages",Object.freeze(["en-US","en"]));' +
          '_def(navigator,"hardwareConcurrency",8);' +
          '_def(navigator,"pdfViewerEnabled",true);' +
          '_def(navigator,"cookieEnabled",true);' +
          '_def(navigator,"onLine",true);' +
          '_def(navigator,"maxTouchPoints",0);' +
          '_def(navigator,"appCodeName","Mozilla");' +
          '_def(navigator,"appName","Netscape");' +
          '_def(navigator,"product","Gecko");' +
          '_def(navigator,"productSub","20030107");' +
          '_def(navigator,"appVersion","5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36");' +
          /* Plugins */
          'try{' +
          'var _fp={name:"PDF Viewer",description:"Portable Document Format",filename:"internal-pdf-viewer",length:0};' +
          'var _fp2={name:"Chrome PDF Viewer",description:"Portable Document Format",filename:"internal-pdf-viewer",length:0};' +
          'var _fp3={name:"Chromium PDF Viewer",description:"Portable Document Format",filename:"internal-pdf-viewer",length:0};' +
          'var _fp4={name:"Microsoft Edge PDF Viewer",description:"Portable Document Format",filename:"internal-pdf-viewer",length:0};' +
          'var _fp5={name:"WebKit built-in PDF",description:"Portable Document Format",filename:"internal-pdf-viewer",length:0};' +
          'var _fpl=Object.assign([_fp,_fp2,_fp3,_fp4,_fp5],{namedItem:function(n){return n.includes("PDF")?_fp:null;},item:function(i){return[_fp,_fp2,_fp3,_fp4,_fp5][i]||null;},refresh:function(){}});' +
          '_def(navigator,"plugins",_fpl);' +
          'var _mt=Object.assign([{type:"application/pdf",description:"PDF",enabledPlugin:_fp,suffixes:"pdf"}],{namedItem:function(t){return t==="application/pdf"?{}:null;},item:function(i){return i===0?{}:null;}});' +
          '_def(navigator,"mimeTypes",_mt);' +
          '}catch(e){}' +
          /* userAgentData */
          'var _br=[{brand:"Not_A Brand",version:"8"},{brand:"Chromium",version:"142"},{brand:"Google Chrome",version:"142"}];' +
          'var _fvl=[{brand:"Not_A Brand",version:"8.0.0.0"},{brand:"Chromium",version:"142.0.7504.61"},{brand:"Google Chrome",version:"142.0.7504.61"}];' +
          'var _ghev=function getHighEntropyValues(){return Promise.resolve({architecture:"x86",bitness:"64",brands:_br,fullVersionList:_fvl,mobile:false,model:"",platform:"Windows",platformVersion:"10.0.0",uaFullVersion:"142.0.7504.61",wow64:false});};' +
          'var _tj=function toJSON(){return{brands:_br,mobile:false,platform:"Windows"};};' +
          '_fn.add(_ghev);_fn.add(_tj);' +
          'var _aud={brands:_br,mobile:false,platform:"Windows",getHighEntropyValues:_ghev,toJSON:_tj};' +
          '_def(navigator,"userAgentData",_aud);' +
          /* Headless detection */
          'try{var _ow=window.outerWidth||window.innerWidth||1280;var _oh=window.outerHeight||window.innerHeight||720;_def(window,"outerWidth",_ow);_def(window,"outerHeight",_oh);}catch(e){}' +
          'try{_def(screen,"availWidth",screen.width||1920);_def(screen,"availHeight",screen.height||1080);_def(screen,"availLeft",0);_def(screen,"availTop",0);}catch(e){}' +
          /* window.chrome — delete and rebuild from scratch */
          'try{delete window.chrome;}catch(e){}try{window.chrome=undefined;}catch(e){}' +
          'window.chrome={};' +
          'window.chrome.app={isInstalled:false,InstallState:{DISABLED:"disabled",INSTALLED:"installed",NOT_INSTALLED:"not_installed"},RunningState:{CANNOT_RUN:"cannot_run",READY_TO_RUN:"ready_to_run",RUNNING:"running"},getDetails:function getDetails(){return null;},getIsInstalled:function getIsInstalled(){return false;},installState:function installState(cb){if(cb)cb("not_installed");},runningState:function runningState(){return"cannot_run";}};' +
          'window.chrome.runtime={id:undefined,connect:function connect(){return{postMessage:function(){},onMessage:{addListener:function(){}},disconnect:function(){}};},sendMessage:function sendMessage(){},onMessage:{addListener:function(){}},onConnect:{addListener:function(){}},getPlatformInfo:function getPlatformInfo(cb){if(cb)cb({os:"win",arch:"x86-64",nacl_arch:"x86-64"});return Promise.resolve({os:"win",arch:"x86-64",nacl_arch:"x86-64"});},getManifest:function getManifest(){return undefined;},getURL:function getURL(){return"";},reload:function reload(){},requestUpdateCheck:function requestUpdateCheck(cb){if(cb)cb("no_update",{});}};' +
          'window.chrome.csi=function csi(){return{startE:Date.now(),onloadT:Date.now(),pageT:1000,tran:15};};' +
          'window.chrome.loadTimes=function loadTimes(){return{requestTime:Date.now()/1000,startLoadTime:Date.now()/1000,commitLoadTime:Date.now()/1000,finishDocumentLoadTime:Date.now()/1000,finishLoadTime:Date.now()/1000,firstPaintTime:Date.now()/1000,firstPaintAfterLoadTime:0,navigationType:"Other",wasFetchedViaSpdy:true,wasNpnNegotiated:true,npnNegotiatedProtocol:"h2",wasAlternateProtocolAvailable:false,connectionInfo:"h2"};};' +
          'window.chrome.storage={local:{get:function(_k,cb){if(cb)cb({});return Promise.resolve({});},set:function(_d,cb){if(cb)cb();return Promise.resolve();}},sync:{get:function(_k,cb){if(cb)cb({});return Promise.resolve({});},set:function(_d,cb){if(cb)cb();return Promise.resolve();}},onChanged:{addListener:function(){}}};' +
          'window.chrome.webstore={onInstallStageChanged:{addListener:function(){}},onDownloadProgress:{addListener:function(){}},install:function(u,s,f){if(f)f({message:"User cancelled install"});},search:function(_,cb){if(cb)cb([]);}};' +
          'window.chrome.i18n={getMessage:function(){return"";},getUILanguage:function(){return"en-US";},detectLanguage:function(t,cb){if(cb)cb({isReliable:false,languages:[{language:"en",percentage:100}]});}};' +
          'window.chrome.dom={openOrClosedShadowRoot:function(){return null;}};' +
          '_fn.add(window.chrome.app.getDetails);_fn.add(window.chrome.app.getIsInstalled);_fn.add(window.chrome.app.installState);_fn.add(window.chrome.app.runningState);' +
          '_fn.add(window.chrome.runtime.connect);_fn.add(window.chrome.runtime.sendMessage);_fn.add(window.chrome.runtime.getPlatformInfo);_fn.add(window.chrome.runtime.getManifest);_fn.add(window.chrome.runtime.getURL);_fn.add(window.chrome.runtime.reload);_fn.add(window.chrome.runtime.requestUpdateCheck);' +
          '_fn.add(window.chrome.csi);_fn.add(window.chrome.loadTimes);' +
          /* WebAuthn/Passkey blocking — keep PublicKeyCredential as stub */
          'try{var _oc=navigator.credentials;' +
          'var _cg=function get(o){if(o&&o.publicKey)return Promise.reject(new DOMException("Not allowed","NotAllowedError"));return _oc?_oc.get.call(_oc,o):Promise.reject(new DOMException("Not allowed","NotAllowedError"));};' +
          'var _cc=function create(o){if(o&&o.publicKey)return Promise.reject(new DOMException("Not allowed","NotAllowedError"));return _oc?_oc.create.call(_oc,o):Promise.reject(new DOMException("Not allowed","NotAllowedError"));};' +
          '_fn.add(_cg);_fn.add(_cc);' +
          'Object.defineProperty(navigator,"credentials",{get:function(){return{get:_cg,create:_cc,preventSilentAccess:function(){return Promise.resolve();},store:function(c){return _oc?_oc.store.call(_oc,c):Promise.resolve();}};},configurable:true});}catch(e){}' +
          'try{if(typeof PublicKeyCredential!=="undefined"){' +
          'var _pkc=function PublicKeyCredential(){throw new TypeError("Illegal constructor");};' +
          '_pkc.isUserVerifyingPlatformAuthenticatorAvailable=function(){return Promise.resolve(false);};' +
          '_pkc.isConditionalMediationAvailable=function(){return Promise.resolve(false);};' +
          '_fn.add(_pkc);_fn.add(_pkc.isUserVerifyingPlatformAuthenticatorAvailable);_fn.add(_pkc.isConditionalMediationAvailable);' +
          'Object.defineProperty(window,"PublicKeyCredential",{value:_pkc,configurable:true,writable:true});' +
          '}}catch(e){}' +
          /* Cleanup Electron globals */
          'try{delete window.Electron;}catch(e){}' +
          'try{delete window.__electron;}catch(e){}' +
          'try{delete window.__electronBinding;}catch(e){}' +
          'try{if(window.process)delete window.process;}catch(e){}' +
          'try{if(window.require)delete window.require;}catch(e){}' +
          'try{if(window.module)delete window.module;}catch(e){}' +
          'try{delete window.Buffer;}catch(e){}' +
          'try{delete window.global;}catch(e){}' +
          'try{delete window.__dirname;}catch(e){}' +
          'try{delete window.__filename;}catch(e){}' +
          /* Remove non-Chrome/automation signals */
          'try{delete window.opr;}catch(e){}' +
          'try{delete window.opera;}catch(e){}' +
          'try{if(navigator.brave)_def(navigator,"brave",undefined);}catch(e){}' +
          'try{if("globalPrivacyControl" in navigator)_def(navigator,"globalPrivacyControl",false);}catch(e){}' +
          'try{delete window.__nightmare;}catch(e){}' +
          'try{delete window.callPhantom;}catch(e){}' +
          'try{delete window._phantom;}catch(e){}' +
          'try{delete window.domAutomation;}catch(e){}' +
          'try{delete window.domAutomationController;}catch(e){}' +
          'try{delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;}catch(e){}' +
          'try{delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;}catch(e){}' +
          'try{delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;}catch(e){}' +
          'try{delete window.controllers;}catch(e){}' +
          'try{delete window.Components;}catch(e){}' +
          'try{delete window.mozInnerScreenX;}catch(e){}' +
          /* Chrome-matching extras */
          'try{if(!window.clientInformation)_def(window,"clientInformation",navigator);}catch(e){}' +
          'try{var _hf=function hasFocus(){return true;};_fn.add(_hf);Object.defineProperty(document,"hasFocus",{value:_hf,configurable:true,writable:true});}catch(e){}' +
          'try{if(!navigator.connection)_def(navigator,"connection",{effectiveType:"4g",rtt:50,downlink:10,saveData:false,addEventListener:function(){},removeEventListener:function(){}});}catch(e){}' +
          'try{if(window.speechSynthesis){var _ogv=window.speechSynthesis.getVoices.bind(window.speechSynthesis);var _fv=[{voiceURI:"Google US English",name:"Google US English",lang:"en-US",localService:true,default:true},{voiceURI:"Google UK English Female",name:"Google UK English Female",lang:"en-GB",localService:false,default:false}];var _gvf=function getVoices(){var r=_ogv();return(r&&r.length)?r:_fv;};_fn.add(_gvf);window.speechSynthesis.getVoices=_gvf;}}catch(e){}' +
          'try{if(typeof Notification!=="undefined")Object.defineProperty(Notification,"permission",{get:function(){return"default";},configurable:true});}catch(e){}' +
          'try{if(navigator.permissions){var _origQ=navigator.permissions.query.bind(navigator.permissions);var _pqf=function query(d){if(d&&(d.name==="notifications"||d.name==="push"))return Promise.resolve({state:"prompt",status:"prompt",onchange:null});return _origQ(d);};_fn.add(_pqf);navigator.permissions.query=_pqf;}}catch(e){}' +
          /* Block service worker registration only on Google domains — SW context has no overrides.
             Spotify and other streaming sites depend on SWs for playback; don't block them. */
          'try{if(navigator.serviceWorker&&/google\\.com|googleapis\\.com|gstatic\\.com|gmail\\.com|youtube\\.com/i.test(window.location.hostname)){var _srf=function register(){return Promise.reject(new DOMException("Failed to register a ServiceWorker","SecurityError"));};_fn.add(_srf);navigator.serviceWorker.register=_srf;}}catch(e){}' +
          '})();';
        var _bypassScript = document.createElement('script');
        _bypassScript.textContent = _bypassCode;
        // Robust injection: wait for documentElement if not yet available
        if (document.head || document.documentElement) {
          (document.head || document.documentElement).prepend(_bypassScript);
          _bypassScript.remove();
        } else {
          // Fallback: inject as soon as the document element is created
          new MutationObserver(function(_, obs) {
            if (document.documentElement) {
              obs.disconnect();
              document.documentElement.prepend(_bypassScript);
              _bypassScript.remove();
            }
          }).observe(document, { childList: true });
        }
      } catch(e) {}
      return; // Don't apply full fingerprint hardening to these sites
    }

    // ── Full fingerprint hardening for all other sites ──────────────────────

    // Remove webdriver flag
    Object.defineProperty(navigator, 'webdriver', { get: () => false, configurable: false });

    // Canvas fingerprint noise
    const _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    function _addNoise(data) {
      for (let i = 0; i < data.length; i += 4) {
        data[i]   = Math.min(255, Math.max(0, data[i]   + ((Math.random() * 2 - 1) | 0)));
        data[i+1] = Math.min(255, Math.max(0, data[i+1] + ((Math.random() * 2 - 1) | 0)));
        data[i+2] = Math.min(255, Math.max(0, data[i+2] + ((Math.random() * 2 - 1) | 0)));
      }
      return data;
    }
    HTMLCanvasElement.prototype.toDataURL = function(...a) {
      const ctx = this.getContext('2d');
      if (ctx) { try { const d = ctx.getImageData(0,0,this.width,this.height); _addNoise(d.data); ctx.putImageData(d,0,0); } catch {} }
      return _origToDataURL.apply(this, a);
    };

    // WebGL vendor/renderer spoofing
    const _patchWebGL = (cls) => {
      if (typeof cls === 'undefined') return;
      const orig = cls.prototype.getParameter;
      cls.prototype.getParameter = function(p) {
        if (p === 37445) return 'Intel Inc.';
        if (p === 37446) return 'Intel Iris OpenGL Engine';
        return orig.call(this, p);
      };
    };
    _patchWebGL(WebGLRenderingContext);
    if (typeof WebGL2RenderingContext !== 'undefined') _patchWebGL(WebGL2RenderingContext);

    // AudioContext noise
    if (typeof AudioBuffer !== 'undefined') {
      const _origGCD = AudioBuffer.prototype.getChannelData;
      AudioBuffer.prototype.getChannelData = function(...a) {
        const d = _origGCD.apply(this, a);
        for (let i = 0; i < d.length; i += 100) d[i] += Math.random() * 0.0001 - 0.00005;
        return d;
      };
    }

    // Block Battery API
    if (navigator.getBattery) {
      Object.defineProperty(navigator, 'getBattery', {
        value: () => Promise.reject(new Error('Blocked')), writable: false, configurable: false,
      });
    }

    // Spoof hardware
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8, configurable: false });
    if ('deviceMemory' in navigator) {
      Object.defineProperty(navigator, 'deviceMemory', { get: () => 8, configurable: false });
    }

    // Empty plugins/mimeTypes
    Object.defineProperty(navigator, 'plugins',   { get: () => [], configurable: false });
    Object.defineProperty(navigator, 'mimeTypes', { get: () => [], configurable: false });

    // Block network info
    if ('connection' in navigator) {
      Object.defineProperty(navigator, 'connection', { get: () => undefined, configurable: false });
    }

    // Block media devices enumeration
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
      const origEnumerate = navigator.mediaDevices.enumerateDevices;
      navigator.mediaDevices.enumerateDevices = function() {
        return origEnumerate.call(this).then(() => []);
      };
    }

    // Stub permissions API — return 'denied' rather than throwing (broken sites reject on error)
    if (navigator.permissions && navigator.permissions.query) {
      navigator.permissions.query = function(desc) {
        return Promise.resolve({ state: 'denied', onchange: null });
      };
    }

    // Spoof navigator identity to match Chrome
    try {
      Object.defineProperty(navigator, 'userAgent',  { get: () => _SPOOF_UA, configurable: false });
      Object.defineProperty(navigator, 'vendor',     { get: () => 'Google Inc.', configurable: false });
      Object.defineProperty(navigator, 'platform',   { get: () => 'Win32', configurable: false });
      Object.defineProperty(navigator, 'language',   { get: () => 'en-US', configurable: false });
      Object.defineProperty(navigator, 'languages',  { get: () => Object.freeze(['en-US', 'en']), configurable: false });
      Object.defineProperty(navigator, 'doNotTrack', { get: () => '1', configurable: false });
    } catch {}

    // Block window.name persistence (cross-origin tracking vector)
    try {
      Object.defineProperty(window, 'name', {
        get: () => '', set: () => {}, configurable: false,
      });
    } catch {}

    // Block Beacon API (used for analytics even after page unload)
    if (navigator.sendBeacon) {
      Object.defineProperty(navigator, 'sendBeacon', {
        value: () => true, writable: false, configurable: false,
      });
    }

    // Spoof screen dimensions to a common resolution (1920x1080)
    try {
      ['width','height','availWidth','availHeight'].forEach((k, i) => {
        const vals = [1920, 1080, 1920, 1080];
        Object.defineProperty(screen, k, { get: () => vals[i], configurable: false });
      });
      Object.defineProperty(screen, 'colorDepth',  { get: () => 24, configurable: false });
      Object.defineProperty(screen, 'pixelDepth',  { get: () => 24, configurable: false });
    } catch {}

    // Spoof navigator.userAgentData (Client Hints API — exposes detailed OS/browser info)
    if ('userAgentData' in navigator) {
      try {
        const _uaBrands = [
          { brand: 'Not_A Brand', version: '8' },
          { brand: 'Chromium', version: '135' },
          { brand: 'Google Chrome', version: '135' },
        ];
        Object.defineProperty(navigator, 'userAgentData', {
          get: () => ({
            brands: _uaBrands,
            mobile: false,
            platform: 'Windows',
            getHighEntropyValues: () => Promise.resolve({
              architecture: 'x86', bitness: '64',
              brands: _uaBrands,
              fullVersionList: [{ brand: 'Not_A Brand', version: '8.0.0.0' }, { brand: 'Chromium', version: '142.0.7504.61' }, { brand: 'Google Chrome', version: '142.0.7504.61' }],
              mobile: false, model: '',
              platform: 'Windows', platformVersion: '10.0.0',
              uaFullVersion: '142.0.7504.61',
            }),
            toJSON: () => ({ brands: _uaBrands, mobile: false, platform: 'Windows' }),
          }),
          configurable: false,
        });
      } catch {}
    }

    // Prevent touch-device detection (fingerprinting via maxTouchPoints)
    try {
      Object.defineProperty(navigator, 'maxTouchPoints', { get: () => 0, configurable: false });
    } catch {}

    // Block speechSynthesis voice enumeration (unique voice list = fingerprint)
    if ('speechSynthesis' in window) {
      try {
        Object.defineProperty(window, 'speechSynthesis', {
          get: () => ({
            getVoices: () => [], speak: () => {}, cancel: () => {},
            pause: () => {}, resume: () => {}, pending: false,
            speaking: false, paused: false,
            addEventListener: () => {}, removeEventListener: () => {},
            dispatchEvent: () => false,
          }),
          configurable: false,
        });
      } catch {}
    }

    // Block keyboard layout fingerprinting (navigator.keyboard)
    if ('keyboard' in navigator) {
      try {
        Object.defineProperty(navigator, 'keyboard', { get: () => undefined, configurable: false });
      } catch {}
    }

    // Neutralize window.opener (prevents tab-napping: opener can redirect parent tab)
    try { if (window.opener !== null) window.opener = null; } catch {}

    // Freeze devicePixelRatio to 1 (reveals display scaling/device type)
    try {
      Object.defineProperty(window, 'devicePixelRatio', { get: () => 1, configurable: false });
    } catch {}

    // ── Timing attack resistance ─────────────────────────────────────────────
    // performance.now() with microsecond precision is a powerful fingerprinting
    // and side-channel attack vector. Jitter it by ±0.1ms (safe for normal use,
    // eliminates high-resolution timing attacks used for cross-site info leaks).
    try {
      const _origNow = performance.now.bind(performance);
      Object.defineProperty(performance, 'now', {
        get: () => () => _origNow() + (Math.random() * 0.2 - 0.1),
        configurable: false,
      });
    } catch {}

    // Suppress performance entry timing data (resource timing reveals CDN infra)
    try {
      const _noop = () => [];
      performance.getEntries        = _noop;
      performance.getEntriesByType  = _noop;
      performance.getEntriesByName  = _noop;
      performance.clearResourceTimings = () => {};
    } catch {}

    // Block CSS font enumeration fingerprinting
    try {
      if (document.fonts && document.fonts.check) {
        const _origCheck = document.fonts.check.bind(document.fonts);
        // Only allow checking fonts that are almost certainly present (system defaults)
        const _safefonts = new Set(['sans-serif','serif','monospace','system-ui',
          'Arial','Times New Roman','Courier New','Georgia','Verdana','Tahoma',
          'Trebuchet MS','Impact','Comic Sans MS']);
        Object.defineProperty(document.fonts, 'check', {
          get: () => (font, text) => {
            const name = (font || '').replace(/^\d+px\s+/, '').replace(/['"]/g, '').trim();
            if (_safefonts.has(name)) return _origCheck(font, text);
            return false; // report all uncommon fonts as missing
          },
          configurable: false,
        });
      }
    } catch {}

    // Block WebBluetooth API (fingerprinting + tracking via peripheral discovery)
    if ('bluetooth' in navigator) {
      try {
        Object.defineProperty(navigator, 'bluetooth', { get: () => undefined, configurable: false });
      } catch {}
    }

    // Block USB API (device fingerprinting vector)
    if ('usb' in navigator) {
      try {
        Object.defineProperty(navigator, 'usb', { get: () => undefined, configurable: false });
      } catch {}
    }

    // Block Serial API
    if ('serial' in navigator) {
      try {
        Object.defineProperty(navigator, 'serial', { get: () => undefined, configurable: false });
      } catch {}
    }

    // Block HID API (Human Interface Device — fingerprinting vector)
    if ('hid' in navigator) {
      try {
        Object.defineProperty(navigator, 'hid', { get: () => undefined, configurable: false });
      } catch {}
    }

    // Neutralize document.referrer (cross-site tracking vector)
    try {
      Object.defineProperty(document, 'referrer', { get: () => '', configurable: false });
    } catch {}

  } catch (e) {
    console.debug('[Lander] Preload error:', e.message);
  }
})();

// ── Media keep-alive guard — injected into the main world before any page script ──
// Uses a <script> element so it runs in the page's JS world (not the isolated
// preload world), meaning our IntersectionObserver and pause overrides are
// installed before YouTube / TikTok / etc. create their observer instances.
// window._rbPanelOpen is set by PANEL_KEEP_ALIVE_JS (main process) when a
// toolbar panel opens, and cleared by PANEL_RESTORE_ALIVE_JS when it closes.
(function injectMediaGuard() {
  try {
    const script = document.createElement('script');
    script.textContent = `(function(){
  if (window._rbGuardInstalled) return;
  window._rbGuardInstalled = true;
  window._rbPanelOpen = false;

  // Wrap IntersectionObserver: while _rbPanelOpen, report every entry as
  // fully visible so YouTube/TikTok players never call .pause() on scroll-out.
  if (window.IntersectionObserver) {
    var _OrigIO = window.IntersectionObserver;
    window.IntersectionObserver = function(cb, opts) {
      return new _OrigIO(function(entries, obs) {
        if (window._rbPanelOpen) {
          entries = entries.map(function(e) {
            return { boundingClientRect:e.boundingClientRect, intersectionRatio:1,
              intersectionRect:e.boundingClientRect, isIntersecting:true,
              rootBounds:e.rootBounds, target:e.target, time:e.time };
          });
        }
        return cb(entries, obs);
      }, opts);
    };
    try { window.IntersectionObserver.prototype = _OrigIO.prototype; } catch(e){}
  }

  // Wrap HTMLVideoElement.pause: drop automatic pauses while panel is open.
  var _origPause = HTMLVideoElement.prototype.pause;
  HTMLVideoElement.prototype.pause = function() {
    if (window._rbPanelOpen) return;
    return _origPause.call(this);
  };

  // Swallow AbortErrors from play() calls that race with blocked pauses.
  var _origPlay = HTMLVideoElement.prototype.play;
  HTMLVideoElement.prototype.play = function() {
    var p = _origPlay.call(this);
    if (p && p.catch) p.catch(function(){});
    return p;
  };

  // ── Passkey / Windows Hello suppressor ────────────────────────────────────
  // Sites call navigator.credentials.get({publicKey:...}) for WebAuthn passkeys.
  // This triggers the Windows Hello system overlay which the user finds intrusive.
  // We silently reject publicKey requests while letting password + identity
  // (FedCM / Google Sign-In) requests through normally.
  if (navigator.credentials && navigator.credentials.get) {
    var _origCredsGet = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = function(opts) {
      if (opts && opts.publicKey && !opts.password && !opts.identity) {
        // Silently reject — pretend no passkey credential was found
        return Promise.reject(
          Object.assign(new DOMException('Not allowed by user', 'NotAllowedError'), { code: 20 })
        );
      }
      return _origCredsGet(opts);
    };
  }
  if (navigator.credentials && navigator.credentials.create) {
    var _origCredsCreate = navigator.credentials.create.bind(navigator.credentials);
    navigator.credentials.create = function(opts) {
      if (opts && opts.publicKey) {
        return Promise.reject(
          Object.assign(new DOMException('Not allowed by user', 'NotAllowedError'), { code: 20 })
        );
      }
      return _origCredsCreate(opts);
    };
  }
})()`;
    // Insert before <head> so it runs before any other scripts
    (document.head || document.documentElement).prepend(script);
    script.remove(); // clean up the element after execution
  } catch (e) {}
})();

// ── Autofill detection ────────────────────────────────────────────────────────
// Watches for login forms and requests credential autofill from the vault.
(function() {
  var _afTimer = null;
  var _lastQuery = 0;

  // Selector prioritised: autocomplete attrs first, then name/id hints, then type
  var USER_SEL =
    'input[autocomplete="username"], input[autocomplete="email"],' +
    'input[type="email"],' +
    'input[name*="user" i], input[name*="email" i], input[name*="login" i],' +
    'input[id*="user" i],   input[id*="email" i],   input[id*="login" i],' +
    'input[placeholder*="email" i], input[placeholder*="username" i],' +
    'input[type="text"]';

  function _visible(el) {
    return el && el.offsetParent !== null && !el.disabled && el.type !== 'hidden';
  }

  function _hasLoginForm() {
    // password field visible, OR a username-like field (for multi-step login)
    if (document.querySelector('input[type="password"]')) return true;
    var cands = Array.from(document.querySelectorAll(USER_SEL));
    return cands.some(function(el) { return _visible(el); });
  }

  function _tryQuery() {
    clearTimeout(_afTimer);
    _afTimer = setTimeout(function() {
      var now = Date.now();
      if (now - _lastQuery < 2000) return; // debounce rapid SPA navigations
      if (_hasLoginForm()) {
        _lastQuery = now;
        ipcRenderer.send('autofill:query', { domain: window.location.hostname });
      }
    }, 600);
  }

  // On initial page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _tryQuery, { once: true });
  } else {
    _tryQuery();
  }

  // Watch for SPA-style dynamic form injection
  if (window.MutationObserver) {
    var _mo = new MutationObserver(function() { if (_hasLoginForm()) _tryQuery(); });
    _mo.observe(document.documentElement, { childList: true, subtree: true });
  }

  // ── Save-password prompt: fires when user submits a login form ─────────────
  var _lastSavePrompt = 0;
  document.addEventListener('submit', function(e) {
    var now = Date.now();
    if (now - _lastSavePrompt < 3000) return;
    var form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    var pwInput = form.querySelector('input[type="password"]');
    if (!pwInput || !pwInput.value) return;
    var userInput = form.querySelector(
      'input[autocomplete="username"], input[autocomplete="email"],' +
      'input[type="email"], input[name*="user" i], input[name*="login" i],' +
      'input[id*="user" i], input[id*="email" i], input[name*="email" i]'
    ) || form.querySelector('input[type="text"]');
    if (!userInput || !userInput.value) return;
    _lastSavePrompt = now;
    ipcRenderer.send('autofill:save-prompt', {
      domain:   window.location.hostname,
      username: userInput.value,
      password: pwInput.value,
    });
  }, true);

  // ── Fill fields when vault sends back credentials ─────────────────────────
  ipcRenderer.on('autofill:fill', function(_e, data) {
    try {
      var nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;

      // Simulate realistic typing events so React/Vue/Angular state machines
      // register the value as user input (not just a programmatic assignment).
      function _fireOnInput(el, val) {
        el.focus();
        nativeSetter.call(el, val);
        // keydown/keyup: some frameworks gate on these to detect keyboard input
        el.dispatchEvent(new KeyboardEvent('keydown',  { bubbles: true, cancelable: true }));
        el.dispatchEvent(new KeyboardEvent('keypress', { bubbles: true, cancelable: true }));
        el.dispatchEvent(new Event('input',            { bubbles: true }));
        el.dispatchEvent(new KeyboardEvent('keyup',    { bubbles: true, cancelable: true }));
        el.dispatchEvent(new Event('change',           { bubbles: true }));
        el.blur();
      }

      // Find the best visible username input — prefer explicit autocomplete attrs
      var allUser = Array.from(document.querySelectorAll(USER_SEL)).filter(_visible);
      var userEl  = allUser[0] || null;

      // Find the best visible password input
      var allPw  = Array.from(document.querySelectorAll('input[type="password"]')).filter(_visible);
      var pwEl   = allPw[0] || null;

      if (userEl && data.username) _fireOnInput(userEl, data.username);
      if (pwEl   && data.password) {
        // Small delay so multi-step forms (e.g. Spotify, Google) have time to
        // show the password field after filling the username.
        setTimeout(function() {
          var pw = Array.from(document.querySelectorAll('input[type="password"]')).filter(_visible)[0];
          if (pw) _fireOnInput(pw, data.password);
        }, pwEl === allPw[0] ? 0 : 400);
      }
    } catch(e) {}
  });
})();

// Expose minimal API to page context
contextBridge.exposeInMainWorld('raw', {
  platform: process.platform,
  getSettings: () => ipcRenderer.invoke('get-settings'),
  on: (channel, cb) => {
    const valid = ['toast', 'settings:set', 'downloads:update'];
    if (valid.includes(channel)) ipcRenderer.on(channel, (_e, ...a) => cb(...a));
  },
  removeAllListeners: ch => ipcRenderer.removeAllListeners(ch),
});