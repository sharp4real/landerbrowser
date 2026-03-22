'use strict';

// Lander Browser — Built-in Blocklist
// Covers ads, trackers, telemetry, fingerprinting, crypto miners, malware, and more.
// This is the fallback when EasyList/EasyPrivacy haven't loaded yet.

const BLOCK_DOMAINS = new Set([
  // ── Google Ads & Tracking ──
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
  'googletagmanager.com', 'googletagservices.com', 'google-analytics.com',
  'ssl.google-analytics.com', 'stats.g.doubleclick.net', 'analytics.google.com',
  'pagead2.googlesyndication.com', 'adservice.google.com', 'adservice.google.co.uk',
  'tpc.googlesyndication.com', 'csi.gstatic.com',

  // ── Meta / Facebook ──
  'connect.facebook.net', 'facebook.net', 'pixel.facebook.com',
  'an.facebook.com', 'graph.facebook.com', 'web.facebook.com',

  // ── Twitter / X ──
  'ads.twitter.com', 'syndication.twitter.com', 'platform.twitter.com',
  't.co', 'analytics.twitter.com',

  // ── Microsoft Telemetry ──
  'bat.bing.com', 'clarity.ms', 'dc.services.visualstudio.com',
  'browser.pipe.aria.microsoft.com', 'vortex.data.microsoft.com',
  'settings-win.data.microsoft.com', 'telemetry.microsoft.com',
  'watson.telemetry.microsoft.com', 'oca.telemetry.microsoft.com',
  'sqm.telemetry.microsoft.com', 'watson.microsoft.com',
  'redir.metaservices.microsoft.com', 'choice.microsoft.com',
  'df.telemetry.microsoft.com', 'reports.wes.df.telemetry.microsoft.com',

  // ── Amazon Ads ──
  'amazon-adsystem.com', 'aax.amazon-adsystem.com',
  'fls-na.amazon.com', 's.amazon-adsystem.com',

  // ── Ad Networks ──
  'adnxs.com', 'advertising.com', 'adtech.com', 'adtechstack.net',
  'rubiconproject.com', 'pubmatic.com', 'openx.net', 'openx.com',
  'contextweb.com', 'casalemedia.com', 'criteo.com', 'criteo.net',
  'outbrain.com', 'taboola.com', 'revcontent.com', 'mgid.com',
  'adsrvr.org', 'quantserve.com', 'addthis.com', 'sharethis.com',
  '3lift.com', 'appnexus.com', 'bidswitch.net', 'smartadserver.com',
  'sovrn.com', 'indexexchange.com', 'districtm.io', 'sharethrough.com',
  'yieldmo.com', '33across.com', 'rhythmone.com', 'improvedigital.com',
  'spotxchange.com', 'spotx.tv', 'freewheel.tv', 'fwmrm.net', 'lkqd.net',
  'media.net', 'zemanta.com', 'adform.net', 'mathtag.com', 'bkrtx.com',
  'rlcdn.com', 'rfihub.com', 'acuityads.com', 'justpremium.com',
  'adhese.com', 'adition.com', 'sonobi.com', 'undertone.com',
  'lijit.com', 'polar.me', 'iponweb.net', 'yieldlove.com',
  'adtelligent.com', 'smartclip.net', 'springserve.com',
  'adaptv.advertising.com', '360yield.com', 'adblade.com',
  'ampliffy.com', 'bidtellect.com', 'conversant.com', 'tremorvideo.com',
  'videologygroup.com', 'advertising.aol.com', 'advertising.yahoo.com',
  'overture.com', 'yldbt.com', 'synacor.com',

  // ── Analytics & Metrics ──
  'scorecardresearch.com', 'omtrdc.net', 'demdex.net',
  'hotjar.com', 'crazyegg.com', 'fullstory.com', 'logrocket.com',
  'heapanalytics.com', 'mixpanel.com', 'amplitude.com',
  'segment.io', 'segment.com', 'intercom.io', 'intercomcdn.com',
  'chartbeat.com', 'chartbeat.net', 'newrelic.com', 'nr-data.net',
  'speedcurve.com', 'sentry.io', 'bugsnag.com', 'rollbar.com',
  'snap.licdn.com', 'tealiumiq.com', 'ensighten.com',
  'optimizely.com', 'abtasty.com', 'vwo.com', 'kameleoon.com',
  'appsflyer.com', 'branch.io', 'adjust.com', 'kochava.com',
  'singular.net', 'tune.com', 'moengage.com', 'clevertap.com',
  'braze.com', 'appboy.com', 'leanplum.com', 'urbanairship.com',

  // ── Fingerprinting ──
  'fingerprintjs.com', 'fingerprint.com', 'fpnpmcdn.net',
  'deviceatlas.com', 'scientiamobile.com', 'maxmind.com',
  'threatmetrix.com', 'iovation.com', 'limelightnetworks.com',
  'tiqcdn.com', 'thirdlight.com',

  // ── Data Brokers / DMPs ──
  'bluekai.com', 'exelate.com', 'nexac.com', 'lotame.com',
  'turn.com', 'agkn.com', 'eyeota.net', 'bizo.com',
  'dotomi.com', 'krxd.net', 'permutive.com', 'audigent.com',
  'zeotap.com', 'neustar.biz', 'acxiom.com', 'experian.com',
  'liveramp.com', 'identitylink.io', 'tapad.com', 'crossix.com',
  'datalogix.com', 'cardlytics.com', 'epsilon.com', 'merkle.com',
  'viant.com', 'adsquare.com', 'factual.com', 'nuedata.com',

  // ── Social Widgets ──
  'platform.linkedin.com', 'badges.linkedin.com',
  'assets.pinterest.com', 'log.pinterest.com',
  'disqus.com', 'disquscdn.com',
  'staticxx.facebook.com', 'web.facebook.com',

  // ── Crypto Miners ──
  'coinhive.com', 'coin-hive.com', 'minero.cc', 'cryptoloot.pro',
  'miner.pr0gramm.com', 'jsecoin.com', 'cryptonight.com',
  'webminepool.com', 'ppoi.org', 'authedmine.com',
  'listat.biz', 'lmodr.biz', 'minecrunch.co', 'minemytraffic.com',

  // ── Malware / Scam ──
  'popcash.net', 'popads.net', 'pop-under.ru',
  'zeroredirect1.com', 'zeroredirect2.com',
  'malvertising.com', 'trafficholder.com',

  // ── Cookie Consent (tracking) ──
  'onetrust.com', 'cookielaw.org', 'cookiebot.com',
  'trustarc.com', 'evidon.com', 'ghostery.com',

  // ── Russian Telemetry ──
  'tns-counter.ru', 'counter.ok.ru', 'mc.yandex.ru',
  'metrika.yandex.ru', 'an.yandex.ru', 'yabs.yandex.ru',
  'mail.yandex.ru', 'carambola.ru',

  // ── Chinese / ByteDance Telemetry ──
  'cnzz.com', 'umeng.com', 'alog.umengcloud.com',
  'mmstat.com', 'alipayobjects.com',
  'snssdk.com', 'bdurl.net',
  'toblog.ctobsnssdk.com', 'byteodg.com',
  'bytedance.com', 'byteimg.com', 'bytefcdn.com',
  'toutiao.com', 'ixigua.com',

  // ── Push Notification Spam ──
  'pushcrew.com', 'onesignal.com', 'pushengage.com',
  'web-push-notifications.com', 'pushassist.com',
  'gravitec.net', 'sendpulse.com', 'pushwoosh.com',

  // ── Session Recording ──
  'mouseflow.com', 'usabilla.com', 'inspectlet.com',
  'luckyorange.com', 'clicktale.com', 'quantummetric.com',
  'glassbox.com', 'sessioncam.com', 'decibel-insight.com',

  // ── A/B Testing / CRO ──
  'googleoptimize.com', 'qubit.com', 'conductrics.com',
  'monetate.net', 'certona.net', 'evergage.com',

  // ── Marketing Automation ──
  'marketo.net', 'pardot.com', 'hubspot.com', 'hubspot.net',
  'hs-analytics.net', 'hs-banner.com', 'hscta.net',
  'eloqua.com', 'responsys.net', 'exacttarget.com',
  'silverpop.com', 'sailthru.com', 'sendgrid.net',
  'mailchimp.com', 'list-manage.com', 'klaviyo.com',

  // ── Retargeting ──
  'rtbhouse.com', 'criteo.com', 'adroll.com', 'perfectaudience.com',
  'triggit.com', 'steelhouse.com', 'fetchback.com',
  'chango.com', 'buyads.com', 'retargeter.com',

  // ── CDN-hosted trackers ──
  'cdn.mxpnl.com', 'js.hs-analytics.net', 'js.hsforms.net',
  'js.hscta.net', 'js.hs-banner.com',

  // ── Supply Side Platforms ──
  'appnexus.com', 'openx.com', 'rubiconproject.com',
  'pubmatic.com', 'rocketfuel.com', 'priceline.com',
  'advertising.microsoft.com', 'media.net',

  // ── Demand Side Platforms ──
  'mediamath.com', 'thetradedesk.com', 'dataxu.com',
  'adobe.com', 'adobedtm.com', 'demdex.com',

  // ── Browser Telemetry / Update pings ──
  'safebrowsing.googleapis.com', 'safebrowsing.google.com',
  'update.googleapis.com', 'clients2.google.com',
  'sb.google.com', 'sb-ssl.google.com',

  // ── Apple Telemetry ──
  'metrics.apple.com', 'pancake.apple.com',
  'xp.apple.com', 'configuration.apple.com',

  // ── General tracker patterns (hosted explicitly) ──
  'tracking.com', 'tracker.com', 'trackingprotection.com',
  'adtrack.com', 'adtracking.com', 'usertrack.com',
  'emailtracking.com', 'mailtracking.com',
  'statcounter.com', 'woopra.com', 'kissmetrics.com',
  'gaug.es', 'getclicky.com', 'clicky.com',

  // ── Supply chain / header bidding ──
  'liveintent.com', 'bidmachine.io', 'emxdgt.com',
  'aniview.com', 'teads.tv', 'teads.com',
  'sharethrough.com', 'triplelift.com', 'nobid.io',
  'nexxen.com', 'unrulymedia.com', 'rhythmone.com',

  // ── Misc high-confidence trackers ──
  'addthis.com', 'outbrain.com', 'taboola.com',
  'revcontent.com', 'mgid.com', 'zergnet.com',
  'ligatus.com', 'nativo.com', 'plista.com',
  'shareaholic.com', 'socialspark.com', 'blogads.com',
  'adsonar.com', 'advertising.com', 'atwola.com',
  'advertising.aol.com',

  // ── Google tracking (not needed for auth — explicitly blockable) ──
  'google-analytics.com', 'ssl.google-analytics.com',
  'googletagmanager.com', 'googletagservices.com', 'adservice.google.com',
  'pagead2.googlesyndication.com', 'tpc.googlesyndication.com',
  'imasdk.googleapis.com', 'fundingchoicesmessages.google.com',
  'stats.g.doubleclick.net', 'cm.g.doubleclick.net',
  '2mdn.net', 'googleadapis.com',

  // ── Ad verification / brand safety ──
  'doubleverify.com', 'cdn.doubleverify.com', 'pub.doubleverify.com',
  'integralads.com', 'pixel.adsafeprotected.com', 'adsafeprotected.com',
  'moatads.com', 'z.moatads.com', 'px.moatads.com',
  'confiant.com', 'cdn.confiant.com',

  // ── Legacy ad networks still active ──
  'zedo.com', 'yieldmanager.com', 'tribalfusion.com',
  'eyeblaster.com', 'mediaplex.com', 'sizmek.com', 'pointroll.com',
  'eyereturn.com', 'specificclick.net', 'adbutter.net',
  'buysellads.com', 'carbonads.com', 'servedby.flashtalking.com',
  'flashtalking.com', 'serving-sys.com', 'bs.serving-sys.com',
  'atdmt.com', 'atlas-analytics.com',

  // ── Quantcast ──
  'quantcast.com', 'quantserve.com', 'pixel.quantserve.com',
  'choice.quantcast.com',

  // ── ID syncing / audience ──
  'ib.adnxs.com', 'secure.adnxs.com', 'nym1.ib.adnxs.com',
  'usermatch.krxd.net', 'sync.mathtag.com', 'match.adsrvr.org',
  'cm.adform.net', 'sync.tidaltv.com', 'px.adhigh.net',
  'acdn.adnxs.com', 'cdn.adnxs.com',

  // ── Affiliate / conversion tracking ──
  'impact.com', 'impactradius.com', 'pxf.io',
  'awin1.com', 'awin.com', 'commission-junction.com', 'cj.com',
  'shareasale.com', 'linksynergy.com', 'rakuten.com',
  'tradedoubler.com', 'affiliatewindow.com', 'zanox.com',

  // ── Modern trackers (2023-2025) ──
  'vercel-insights.com', 'va.vercel-insights.com',
  'clarity.ms', 'c.clarity.ms',
  'cdn.cookielaw.org', 'optanon.blob.core.windows.net',
  'cdn.privacy-center.org',
  'privacyportal.onetrust.com', 'geolocation.onetrust.com',
  'cdn.segment.com', 'api.segment.io',
  'cdn4.mxpnl.com', 'api.mixpanel.com',
  'cdn.heapanalytics.com', 'heapanalytics.com',
  'edge.fullstory.com', 'rs.fullstory.com',
  'widget.intercom.io', 'api.intercom.io', 'nexus.intercom.io',
  'js.sentry-cdn.com', 'browser.sentry-cdn.com', 'o0.ingest.sentry.io',
  'cdn.lr-ingest.io', 'r.lr-ingest.io',
  'cdn.mouseflow.com',
  'cdn.amplitude.com', 'api.amplitude.com', 'api2.amplitude.com',
  'cdn.rudderlabs.com', 'api.rudderlabs.com',
  'edge.tealiumiq.com', 'collect.tealiumiq.com',
  'px.moatads.com', 'z.moatads.com',
  'tr.snapchat.com', 'sc-static.net',
  'px.ads.linkedin.com', 'snap.licdn.com',
  'ct.pinterest.com', 'ads.pinterest.com',
  'analytics.twitter.com', 'ads.twitter.com', 'static.ads-twitter.com',
  't.co',
  'analytics.tiktok.com', 'log.tiktok.com',
  'bat.bing.com', 'c.bing.com',
  'mc.yandex.com', 'mc.yandex.ru',
  'counter.ok.ru',
  'cdp.customer.io', 'track.customer.io',
  'cdn.pendo.io', 'app.pendo.io', 'data.pendo.io',
  'cdn.walkme.com', 'ec.walkme.com',
  'cdn.appcues.com', 'api.appcues.com',
  'js.driftt.com', 'event.logrocket.com',
  'analytics.posthog.com', 'us.i.posthog.com', 'eu.i.posthog.com',
  'plausible.io',

  // ── CNAME-cloaked trackers (common setups) ──
  'metrics.icloud.com', 'weather-analytics.apple.com',
  'ep1.adtrafficquality.google', 'ep2.adtrafficquality.google',

  // ── Prebid.org / Header bidding infrastructure ──
  'prebid.adnxs.com', 'ib.anycast.adnxs.com',
  'sync.teads.tv', 'a.teads.tv', 'p.teads.tv',
  'hbopenbid.pubmatic.com', 'ssbsync.smartadserver.com',
  'ads.pubmatic.com', 'image2.pubmatic.com', 'image6.pubmatic.com',
  'simage2.pubmatic.com',

  // ── Demand-side platforms (DSPs) ──
  'bidder.criteo.com', 'static.criteo.net', 'sslwidget.criteo.com',
  'bidder.audigent.com', 'match.audigent.com',
  'exchange.mediavine.com',
  'pb.meitu.com',

  // ── Extended fingerprinting infrastructure ──
  'h.clarity.ms', 'www.clarity.ms',
  'fpcdn.io', 'api.fpjs.io', 'eu.api.fpjs.io',
  'pro.ipdata.co', 'api.ipdata.co',
  'extreme-ip-lookup.com', 'ipinfo.io', 'ipapi.co',
  'freegeoip.app', 'geolocation-db.com',

  // ── Data brokers / identity resolution ──
  'sync.intentiq.com', 'cdn.intentiq.com',
  'usersync.uid2.prod.euid.eu', 'global.idsync.rlcdn.com',
  'usersync.id5-sync.com', 'id5-sync.com', 'id5.io',
  'publisher.linksynergy.com', 'click.linksynergy.com',

  // ── Video ad networks ──
  'ads.yieldmo.com', 'ads.sharethrough.com',
  'player.unrulymedia.com', 'targeting.unrulymedia.com',
  'freewheel.tv', 'ads.stickyadstv.com',
  'x.bidswitch.net', 'ssp.launch.bidswitch.net',
  'usersync.bidswitch.net', 'prebid.bidswitch.net',

  // ── Consent management / privacy washing ──
  'api.consentframework.com', 'cdn.consentframework.com',
  'cmpv2.quantcast.com', 'quantcast.mgr.consensu.org',
  'vendor-list.consensu.org',
  'cdn.privacy-mgmt.com', 'pm.w55c.net',

  // ── Ad fraud / viewability measurement ──
  'openadstat.com', 'api.openadstat.com',
  'cdn.branch.io', 'device.branch.io',
  'app.link', 'bnc.lt',
  'e.crashlytics.com', 'settings.crashlytics.com',

  // ── In-app / mobile ad SDKs (web versions) ──
  'ads.mopub.com', 'ads.smartadserver.com',
  'mobile.smartadserver.com', 'sdk.smartadserver.com',
  'sdk-syndication.sharethis.com',
  'opmtag.com', 'cdn.opmtag.com',

  // ── News/content trackers ──
  'beacon.krxd.net', 'cdn.parsely.com', 'api.parsely.com',
  'p.parsely.com', 'srv.stackcommerce.com',
  'cdn.viglink.com', 'api.viglink.com',
  'skimresources.com', 'redirectingat.com', 'go.redirectingat.com',

  // ── Extended social pixels ──
  'geo.yahoo.com', 'ups.analytics.yahoo.com',
  'consent.yahoo.com', 'sp.analytics.yahoo.com',
  'analytics.yahoo.com', 'ads.yahoo.com',
  'tracking.vk.com', 'ads.vk.com', 'top.vk.com',

  // ── Ad injection / overlay networks ──
  'pagefair.com', 'pagefair.net',
  'adblade.com', 'adblade.net',
  'content.adblade.com', 'engine.adblade.com',

  // ── Telemetry beacons commonly embedded in pages ──
  'tr.outbrain.com', 'tr-edge.outbrain.com',
  'amplify.outbrain.com', 'widgets.outbrain.com',
  'cdn.taboola.com', 'trc.taboola.com',
  'log.rc.yahoo.com', 'b.rc.yahoo.com',

  // ── AI / ML data harvesting ──
  'api.openai.com', 'o1.ingest.sentry.io',
  'telemetry.openai.com',

  // ── Extended modern ad tech (2024–2025) ──
  'shbcdn.com', 'shb.richaudience.com',
  'cdn.traffstars.com', 'rtb.traffstars.com',
  'hb.vntsm.com', 'ssp.vntsm.com',
  'ads.trafficjunky.net', 'static.trafficjunky.net',
  'adn.ebdr1.com', 'adn.ebdr2.com',
  'cdn.undertone.com', 'supply.undertone.com',
  'sync.1rx.io', 'ads.1rx.io',
  'sync.adstanding.com',
  'cdn.adskeeper.co.uk', 'trc.adskeeper.co.uk',
  'rtb.gumgum.com', 'g2.gumgum.com',
  'sync.gumgum.com', 'usersync.gumgum.com',
  'ads.gumgum.com', 'assets.gumgum.com',
  'rtb.myfinance.com',
  'cdn.silverpush.co', 'rtb.silverpush.co',
  'ssp.aniview.com', 'player.aniview.com',
  'cdn.aniview.com',
  'sync.samba.tv', 'pixel.samba.tv',
  'cdn.doceree.com', 'log.doceree.com',
  'rtb.nextmillennium.io',
  'pixel.onaudience.com', 'sync.onaudience.com',

  // ── Extended telemetry endpoints ──
  'telemetry.mozilla.org', 'normandy.cdn.mozilla.net',
  'push.services.mozilla.com',
  'incoming.telemetry.mozilla.org',
  'crash-stats.mozilla.com',
  'telemetry.kafka.mozilla.com',
  'data.mozilla.com', 'addon.mozilla.org',
  'telemetry.apple.com',
  'metrics2.data.hicloud.com', 'log.hicloud.com',
  'metrics.samsung.com', 'samsungads.com',
  'analytics.samsung.com', 'log.samsungosp.com',
  'telemetry.dropbox.com', 'telemetry-client.dropbox.com',
  'error-reporting.dropbox.com',
  'client-telemetry.roblox.com', 'ecsv2.roblox.com',
  'clientsettings.roblox.com',
  'log.byteoversea.com', 'log-oversea.bytedance.com',

  // ── More CMP / consent washing ──
  'cdn.privacy-center.org', 'consent.cookiebot.com',
  'consentcdn.cookiebot.com', 'imgsct.cookiebot.com',
  'consentmanager.net', 'cdn.consentmanager.net',
  'delivery.consentmanager.net',
  'cmpv2.quantcast.com', 'cmp.quantcast.com',
  'cdn.cookielaw.org', 'privacyportal.cookielaw.org',
  'geolocation.onetrust.com',
  'js.cookiefirst.com', 'api.cookiefirst.com',
  'cdn.iubenda.com', 'cs.iubenda.com',
  'api.iubenda.com',
  'usercentrics.eu', 'app.usercentrics.eu',
  'aggregated-consent.usercentrics.eu',
  'privacy.api.bbc.com', 'privacy-center.bbc.com',

  // ── More identity resolution / cross-site tracking ──
  'connect.liveramp.com', 'authentication.liveramp.com',
  'ats.rlcdn.com', 'ats-wrapper.rlcdn.com',
  'cdn.digitalenvoy.net',
  'global.idsync.rlcdn.com',
  'cm.adform.net', 'track.adform.net',
  'a.ad.gt', 'sync.ad.gt',
  'login.dotomi.com', 'ad.dotomi.com',
  'cm.hivestack.com',
  'sync.richaudience.com',
  'api.lucidity.inc',

  // ── Extended fingerprinting services ──
  'geo2.adobe.com', 'dpm.demdex.net',
  'adobedc.net', 'edgegateway.adobe.com',
  'cm.everesttech.net',
  'cdn.alocdn.com',
  'neodatagroup.com', 'cdn.neodatagroup.com',
  'idsync.pangle-ads.com',
  'jf.appsflyer.com', 'launches.appsflyer.com',
  'register.go.affec.tv',
  'track.fivetran.com',

  // ── Extended session recording & heatmaps ──
  'static.zdassets.com', 'ekr.zdassets.com',
  'tracking.g2crowd.com',
  'api.usersnap.com', 'widget.usersnap.com',
  'cdn.smartlook.com', 'web-sdk.smartlook.com',
  'rec.smartlook.com', 'manager.smartlook.com',
  'sdk.split.io', 'sdk-telemetry.split.io',
  'events.split.io',
  'cdn.optimove.net', 'api3.optimove.net',
  'track.kameleonads.com',
  'eu.posthog.com', 'us.posthog.com',
  'cdn.reamaze.com', 'api.reamaze.com',

  // ── Extended marketing automation / email tracking ──
  'trk.klclick.com', 'cta-redirect.hubspot.com',
  'forms.hsforms.com', 'api.hsforms.com',
  'js.hsforms.net', 'js.hscollectedforms.net',
  'collect.usefathom.com',
  'api.convertflow.com',
  'cdn.convertbox.com',
  'sdk.logrocket.com', 'ingest.logrocket.com',
  'sessions.bugsnag.com', 'notify.bugsnag.com',
  'cdn.pendo.io',

  // ── Extended ad fraud / viewability ──
  'geo2.doubleverify.com', 'rtb.doubleverify.com',
  'pub.doubleverify.com',
  'aa.agkn.com', 'bcp.crwdcntrl.net',
  'dis.us.criteo.com', 'gum.criteo.com',
  'rtb.criteo.com',
  'pixel.rubiconproject.com',
  'pixel.advertising.com',
  'optout.advertising.com',

  // ── Extended push notifications ──
  'push.zemanta.com',
  'pn-cdn.braze.com', 'dev.appboy.com',
  'sdk.iad-01.braze.com', 'sdk.fra-01.braze.eu',
  'endpoint.collection.yahoo.com',
  'notifications.googlecode.com',
]);

// Regex patterns for catching tracker subdomains dynamically
const BLOCK_PATTERNS = [
  /^ads?\d*\./i,
  /^ad\d+\./i,
  /\.ads?\./i,
  /^track(ing|er)?\d*\./i,
  /^pixel\d*\./i,
  /^beacon\d*\./i,
  /^telemetry\d*\./i,
  /^analytics?\d*\./i,
  /^collect\d*\./i,
  /^metrics?\d*\./i,
  /^stats?\d*\./i,
  /^(gtm|tag|stm)\./i,
  /^log(ger|ging)?\d*\./i,
  /^event(s)?\./i,
  /^ping\./i,
  /^hit\./i,
  /^impression\./i,
  /^conv(ersion)?\./i,
  /^retarget(ing)?\./i,
  /^remarketing\./i,
  /^dmp\./i,
  /^audience\./i,
  /^segment\./i,
  /^report(ing|s)?\./i,
  /^miner\./i,
  /^mine\./i,
  /^crypto.*mine/i,
  // Extended patterns (also used in strict mode)
  /^syn(c|chronize)?\d*\./i,          // ID sync endpoints
  /^usersync\./i,
  /^idsync\./i,
  /^match\d*\./i,                      // cookie matching
  /^cm\d*\./i,                         // cookie matching CDNs
  /^rtb\d*\./i,                        // real-time bidding
  /^prebid\d*\./i,
  /^bid(der|ding|s)?\d*\./i,
  /^hb\./i,                            // header bidding
  /^ssp\d*\./i,                        // supply-side platforms
  /^dsp\d*\./i,                        // demand-side platforms
  /^tr(k|acking)?\d*\./i,              // short tracking subdomains
  /^\w+\.pixel\./i,                    // *.pixel.domain
  /^identity\./i,                      // identity resolution
  /^consent\./i,                       // consent farming infra
  /^cmp\d*\./i,                        // consent management platforms
  /^(ad|ads)\d*\-/i,                   // ad-prefix hyphenated subdomains
  /^telemetry\d*\./i,                  // additional telemetry catch-all
  /^crash(report|reporter|log)?\./i,   // crash reporting
  /^error(log|report|track)?\./i,      // error telemetry
  /^perf(ormance)?log\./i,             // performance logging
  /^(ab|a\/b|split)\d*\./i,            // A/B test infrastructure
  /^heatmap\d*\./i,                    // heatmap services
  /^session(record|replay|cam)?\./i,   // session recording
  /^fingerprint\d*\./i,                // fingerprinting services
  /^geo(ip|locate|location)?\d*\./i,   // IP geolocation trackers
  /^measure\d*\./i,                    // measurement endpoints
  /^monit(or|oring)?\d*\./i,           // monitoring/telemetry
];

// Never block these no matter what
const WHITELIST = new Set([
  'youtube.com', 'www.youtube.com', 'youtu.be',
  'twitter.com', 'x.com',
  'instagram.com', 'www.instagram.com',
  'facebook.com', 'www.facebook.com', 'm.facebook.com',
  'reddit.com', 'www.reddit.com', 'old.reddit.com',
  'twitch.tv', 'www.twitch.tv', 'static.twitchsvc.net',
  'discord.com', 'discordapp.com', 'discordcdn.com',
  'slack.com', 'slack-edge.com',
  'zoom.us', 'us02web.zoom.us',
  'netflix.com', 'www.netflix.com',
  'spotify.com', 'open.spotify.com',
  'github.com', 'raw.githubusercontent.com', 'objects.githubusercontent.com',
  'gitlab.com',
  'stackoverflow.com', 'stackexchange.com',
  'wikipedia.org', 'wikimedia.org',
  'google.com', 'www.google.com', 'accounts.google.com', 'mail.google.com',
  'gstatic.com', 'googleapis.com', 'google.co.uk', 'google.de',
  'amazon.com', 'www.amazon.com', 'images-na.ssl-images-amazon.com',
  'cloudfront.net', 'fastly.net', 'akamaized.net', 'akamai.net',
  'cdn77.com', 'cdnjs.cloudflare.com', 'cloudflare.com',
  'unpkg.com', 'jsdelivr.net',
  'apple.com', 'icloud.com', 'mzstatic.com',
  'microsoft.com', 'live.com', 'office.com', 'microsoft365.com',
  'nytimes.com', 'theguardian.com', 'bbc.com', 'bbc.co.uk',
  'cnn.com', 'reuters.com', 'apnews.com',
]);

function isWhitelisted(host) {
  if (WHITELIST.has(host)) return true;
  for (const w of WHITELIST) {
    if (host.endsWith('.' + w)) return true;
  }
  return false;
}

// Additional domains blocked only in Strict mode
const STRICT_BLOCK_DOMAINS = new Set([
  // Extended analytics
  'matomo.cloud', 'piwik.pro', 'mouseflow.io', 'heatmap.com',
  'convertkit.com', 'activecampaign.com', 'getresponse.com',
  'campaign-monitor.com', 'constantcontact.com', 'mailerlite.com',
  'sendpulse.com', 'drip.com', 'ontraport.com',
  // Extended ad networks
  'ads.yahoo.com', 'gemini.yahoo.com', 'oath.com', 'verizonmedia.com',
  'yimg.com', 'storage.googleapis.com', /* used by some ad SDKs */
  'pagead2.googlesyndication.com', 'tpc.googlesyndication.com',
  'fundingchoicesmessages.google.com',
  'imasdk.googleapis.com',
  // Social tracking pixels
  'px.ads.linkedin.com', 'snap.licdn.com', 'tr.snapchat.com',
  'sc-static.net',
  'ads.pinterest.com', 'ct.pinterest.com', 'trk.pinterest.com',
  'ads-twitter.com', 'static.ads-twitter.com',
  // TikTok analytics, ads, logging — strict mode extras
  'ads.tiktok.com', 'business.tiktok.com',
  'analytics.tiktok.com', 'log.tiktok.com', 'log-va.tiktok.com',
  'log-sg.tiktok.com', 'mon.tiktok.com', 'stats.tiktok.com',
  'event.tiktok.com', 'metrics.tiktok.com', 'monitor.tiktok.com',
  'tracker.tiktok.com', 'snssdk.com', 'bdurl.net', 'musical.ly',
  // More fingerprinting services
  'cdn.iovation.com', 'mpsnare.iesnare.com', 'ci.mpsnare.iesnare.com',
  'kochava.com', 'branch.io', 'app.link', 'stp.link',
  // Extended push/notification spam
  'webpushr.com', 'aimtell.com', 'subscribers.com',
  'perfectaudience.com', 'retargetly.com', 'nexus.ensighten.com',
  'onesignal.com', 'pushcrew.com', 'pushassist.com', 'pushalert.co',
  // Content recommendation / sponsored content
  'ligatus.com', 'nativo.com', 'plista.com', 'strossle.com',
  'teads.tv', 'teads.com', 'yieldmo.com', 'disqus.com', 'disquscdn.com',
  // Extended session recording
  'record.cursors.io', 'recording.userflow.com', 'sprig.com',
  // Identity resolution / cross-site tracking
  'liveintent.com', 'thrtle.com', 'id5-sync.com', 'id5.io',
  'prebid.org', 'openx.org',
  'connectid.conversant.com', 'token.rubiconproject.com',
  'sync.rubiconproject.com', 'tap2.rubiconproject.com',
  'dis.us.criteo.com', 'gum.criteo.com',
  'usersync.gumgum.com', 'sync.gumgum.com',
  'usersync.improve-digital.net', 'sync.sharethis.com',
  // Extended fingerprinting
  'tiqcdn.com', 'tags.tiqcdn.com',
  'tags.bkrtx.com',
  // E-commerce tracking
  'track.omnisend.com', 'trk.klaviyomail.com',
  'ct.pinterest.com', 'trk.pinterest.com',
  'p.typekit.net', /* Adobe Fonts analytics ping */
]);

// Strict-mode URL path patterns (matching known tracking endpoints)
const STRICT_PATH_PATTERNS = [
  /\/track(ing|er)?\//i,
  /\/collect\//i,
  /\/pixel(\.gif|\.png|\.php)?\b/i,
  /\/beacon\//i,
  /\/analytics\//i,
  /\/metrics\//i,
  /\/impression\//i,
  /\/conversion\//i,
  /\/event(s)?\//i,
  /[?&](utm_|fbclid|gclid|msclkid|ttclid|twclid|dclid|sscid|igshid|mc_eid|_ga|_gl)=/i,
  /\/1x1\.(gif|png|jpg)\b/i,          // 1×1 tracking pixels
  /\/tr\.gif\b/i,
  /\/b\/ss\//i,                        // Adobe Analytics
  /\/activityi\b/i,                    // Google activity tracking
  /\/bat\.bing\b/i,
  /\/collect\?v=/i,                    // GA collect endpoint
  /\/r\/collect\b/i,                   // GA batch
  /\/g\/collect\b/i,                   // GA4 collect
  /\/td\.gif\b/i,
  /\/utag\/sync/i,                     // Tealium sync
];

// extraDomains: optional Set of additional domains from locally-cached filter lists
function shouldBlock(url, adblockEnabled, level, extraDomains) {
  if (!adblockEnabled) return false;
  const strict = (level === 'strict');

  try {
    const urlObj = new URL(url);
    const host = urlObj.hostname.toLowerCase().replace(/^www\./, '');
    const parts = host.split('.');

    // Explicit block lists are checked BEFORE whitelist so tracker subdomains of
    // whitelisted parent domains (e.g. imasdk.googleapis.com < googleapis.com)
    // are still caught. A domain in BLOCK_DOMAINS always wins.
    if (BLOCK_DOMAINS.has(host)) return true;
    for (let i = 1; i < parts.length - 1; i++) {
      if (BLOCK_DOMAINS.has(parts.slice(i).join('.'))) return true;
    }

    // Locally-cached filter list rules (EasyList, EasyPrivacy) — checked before whitelist
    // so filter-list rules override the whitelist for tracking subdomains.
    if (extraDomains && extraDomains.size > 0) {
      if (extraDomains.has(host)) return true;
      for (let i = 1; i < parts.length - 1; i++) {
        if (extraDomains.has(parts.slice(i).join('.'))) return true;
      }
    }

    if (isWhitelisted(host)) return false;

    // Strict mode only: additional domains
    if (strict && STRICT_BLOCK_DOMAINS.has(host)) return true;
    if (strict) {
      for (let i = 1; i < parts.length - 1; i++) {
        if (STRICT_BLOCK_DOMAINS.has(parts.slice(i).join('.'))) return true;
      }
    }

    // Moderate + Strict: subdomain patterns (safe — won't break normal site functionality)
    for (const pattern of BLOCK_PATTERNS) {
      if (pattern.test(host)) return true;
    }

    // Moderate: high-confidence URL path patterns for known tracking endpoints
    // (1×1 pixels, beacon GIFs, Google Analytics collect endpoints, etc.)
    const moderatePathPatterns = [
      /\/1x1\.(gif|png|jpg)\b/i,
      /\/pixel\.(gif|png|php)\b/i,
      /\/tr\.gif\b/i,
      /\/collect\?v=\d/i,              // Google Analytics collect
      /\/r\/collect\b/i,               // GA batch endpoint
      /\/g\/collect\b/i,               // GA4 collect endpoint
      /\/b\/ss\//i,                    // Adobe Analytics
      /\/activityi\b/i,                // Google activity
      /\/bat\.bing\b/i,                // Bing Ads
      /\/td\.gif\b/i,                  // Tealium beacon
      /\/utag\/sync/i,                 // Tealium sync
      /\/pxl\.(gif|php)\b/i,           // Generic pixel endpoints
      /\/beacon\.(gif|php|js)\b/i,     // Beacon endpoints
      /\/hit\.(gif|php)\b/i,           // Hit counters
      /\/__utm\.gif\b/i,               // Legacy GA pixel
      /\/impression\.(gif|php)\b/i,    // Impression trackers
      /[?&](utm_|fbclid|gclid|msclkid|ttclid|twclid|dclid|sscid|igshid|mc_eid|_ga|_gl)=/i,
    ];
    for (const pattern of moderatePathPatterns) {
      if (pattern.test(urlObj.pathname) || pattern.test(urlObj.search)) return true;
    }

    // Strict-only: extra URL path patterns for tracking endpoints
    if (strict) {
      for (const pattern of STRICT_PATH_PATTERNS) {
        if (pattern.test(urlObj.pathname) || pattern.test(urlObj.search)) return true;
      }
    }
  } catch (e) {
    return false;
  }

  return false;
}

module.exports = { shouldBlock, isWhitelisted, BLOCK_DOMAINS, BLOCK_PATTERNS, WHITELIST };