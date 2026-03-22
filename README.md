<<<<<<< HEAD
Soon.
=======
**Lander Browser**

A privacy-first desktop browser built on Electron. Zero telemetry, zero data collection — just a fast, clean browser built entirely for you.

---

## Core Features

### Privacy & Security
| Feature | Description |
|---------|-------------|
| **Ad & Tracker Blocking** | 500+ built-in blocked domains + 28 regex patterns, with optional EasyList, EasyPrivacy, and Fanboy's Annoyance List |
| **Fingerprint Spoofing** | Canvas, WebGL, AudioContext, font enumeration, and hardware API noise injection |
| **WebRTC Protection** | Forces relay-only mode — your real IP is never exposed |
| **User Agent Masking** | Blends in with standard desktop browsers — your real browser identity is never revealed |
| **Tracking Parameter Stripping** | Removes UTM codes, fbclid, gclid, and 60+ other tracking parameters from every URL |
| **DoNotTrack + Sec-GPC** | Sends privacy-respecting headers on every request |
| **Third-Party Cookie Blocking** | Cross-site isolation prevents ad network profiling |
| **Telemetry Blocking** | Blocks OS and browser phone-home requests |
| **Strict or Moderate Blocking** | Choose between aggressive or balanced ad blocking |
| **Ignore Mode (Incognito)** | Fully isolated private window — no history, no cookies, no trace |

### Location & Identity
| Feature | Description |
|---------|-------------|
| **Location Masking** | Spoof GPS coordinates to any of 51 cities across 5 regions worldwide |
| **Poison Data** | Flood trackers with fake behavioural signals to hide in plain sight |
| **Whitelist Manager** | Trust specific domains — bypass blocking for sites you control |

### Media & Video
| Feature | Description |
|---------|-------------|
| **Video Downloader** | Download from 1,000+ sites (YouTube, Twitter, Reddit, TikTok, etc.) via yt-dlp |
| **Picture-in-Picture** | Pop any video out of the page into a floating overlay |
| **Tab Audio Manager** | See all playing audio tabs — mute, skip, or jump to any tab |
| **Video Speed Control** | Fine-grained playback speed (0.25× – 3×) injected into any video |

### Built-in Add-Ons (Marketplace)
| Extension | Category |
|-----------|----------|
| Dark Mode | Appearance |
| Reader Mode | Productivity |
| Focus Mode | Productivity |
| Grayscale | Appearance |
| Night Filter | Appearance |
| Font Boost | Accessibility |
| Custom Cursor | Appearance |
| No Animations | Accessibility |
| High Contrast | Accessibility |
| Neon Glow | Appearance |
| Sticky Notes | Productivity |
| Image Zoom | Productivity |
| Video Speed | Media |
| PiP Mode | Media |
| Highlight Links | Accessibility |
| Scroll Progress | Appearance |
| Word Count | Productivity |
| Anti-Tracking | Privacy |
| Print Clean | Productivity |
| Smooth Scroll | Appearance |
| Smart Copy | Productivity |
| Hide Comments | Productivity |
| Link Preview | Productivity |
| Auto Scroll | Productivity |
| Page Zoom | Accessibility |
| YouTube Ad Skipper | Media |
| Serif Mode | Appearance |
| Scroll to Top | Productivity |
| Code Highlight | Appearance |
| URL Cleaner | Privacy |
| Distraction Block | Privacy |
| Low Data Mode | Performance |

### Productivity Tools
| Tool | Description |
|------|-------------|
| **Notes** | Local markdown-compatible notepad with auto-save |
| **Calculator** | Scientific calculator with full expression support |
| **Downloads Manager** | Live speed/ETA, active downloads, full searchable history |
| **Bookmarks** | Search, organize, and manage your bookmarks |
| **Full History** | Searchable history with date filters and bulk delete |
| **Page Translation** | Translate any page to your language instantly |
| **Screenshot Tool** | Capture full page or drag a region (Ctrl+Shift+S) |
| **Find on Page** | Ctrl+F search with match count and navigation |
| **Zoom Control** | Per-tab zoom with persistent memory |
| **AI Summarizer** | Summarize any page with OpenAI, Gemini, DeepSeek, or Claude |
| **Tab Groups** | Organize tabs into named, colour-coded groups |
| **Memory Saver** | Automatically suspends idle tabs to free RAM |
| **Custom CSS/JS Plugins** | Inject your own stylesheets and scripts into every page |
| **Password Manager** | Store and autofill credentials locally |
| **Sidebar** | Pin any website for persistent one-click access |

### Interface & Customization
| Feature | Description |
|---------|-------------|
| **Themes** | 76 themes across 6 categories — including Frutiger Aero, Nord, Dracula, Catppuccin, Synthwave, and more |
| **9 Accent Colors** | White, orange, green, pink, red, purple, yellow, grey, turquoise |
| **Custom Wallpapers** | Static images or live video wallpapers (MP4/WebM) with built-in options |
| **Vertical Tabs** | Move the tab strip to a collapsible left sidebar |
| **Compact Mode** | Reduced chrome height for more content area |
| **Quick Links** | Customizable shortcuts below the new tab search bar |
| **Weather Widget** | Current conditions on new tab via wttr.in |
| **Custom Dropdowns** | Styled select menus throughout settings for a polished look |
| **Wobble Window Effect** | Compiz-inspired elastic window drag animation (experimental) |
| **Discord Rich Presence** | Optional activity status in Discord (off by default) |

---

## Quick Start

```bash
git clone https://github.com/sharp4real/landerbrowser.git
cd landerbrowser
npm install
npm start
```

### Build for your platform

```bash
npm run build:win      # Windows (.exe installer)
npm run build:mac      # macOS (.dmg)
npm run build:linux    # Linux (.AppImage / .deb)
npm run build:flatpak  # Flatpak (requires flatpak & flatpak-builder)
```

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+T | New tab |
| Ctrl+W | Close tab |
| Ctrl+L | Focus address bar |
| Ctrl+R / F5 | Reload |
| Ctrl+F | Find on page |
| Ctrl+Shift+S | Screenshot / snipping tool |
| Ctrl+Shift+I | Open DevTools |
| Alt+Left / Right | Back / Forward |
| Ctrl+Tab | Next tab |
| Ctrl+Shift+Tab | Previous tab |
| Ctrl+1–9 | Switch to tab N |
| Ctrl+Shift+N | Open Ignore (private) window |
| Ctrl++ / Ctrl+- | Zoom in / out |
| Ctrl+0 | Reset zoom |

---

## Privacy Philosophy

Lander Browser is built on a single principle: **your browsing is your business.**

- No servers receive your browsing data
- No analytics, no crash beacons (unless you opt in)
- No monetisation of your attention or data
- Filter rules are fetched from community-maintained open-source lists and cached locally
- Passwords and history live only on your device

**Filter list credits:** Lander Browser uses rules from [EasyList](https://easylist.to), EasyPrivacy, and Fanboy's Annoyance List — open-source community projects licensed under CC BY-SA 3.0. We gratefully acknowledge the EasyList maintainers and contributors.

---

## Tech Stack

- **Electron** 41.0.3
- **Chromium** (via Electron)
- **yt-dlp** for video downloading
- **discord-rpc** for optional Rich Presence
- Pure HTML/CSS/JS — no frontend framework

---

## License

See [LICENSE](LICENSE) for details.
>>>>>>> 4c193dc (Release v1.0.0)
