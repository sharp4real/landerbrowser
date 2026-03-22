; installer.nsh — Custom registry writes so Lander Browser appears in
; Windows Settings › Default Apps after installation.
; Follows the exact same structure Chrome/Edge use (StartMenuInternet tree).
; electron-builder calls !macro customInstall / customUnInstall automatically.

!macro customInstall
  ; ── ProgID (LanderBrowserHTML) ───────────────────────────────────────────────
  WriteRegStr HKCU "Software\Classes\LanderBrowserHTML" \
              "" "Lander Browser HTML Document"
  WriteRegStr HKCU "Software\Classes\LanderBrowserHTML" \
              "URL Protocol" ""
  WriteRegStr HKCU "Software\Classes\LanderBrowserHTML\DefaultIcon" \
              "" "$INSTDIR\Lander Browser.exe,0"
  WriteRegStr HKCU "Software\Classes\LanderBrowserHTML\shell\open\command" \
              "" '"$INSTDIR\Lander Browser.exe" "%1"'

  ; ── StartMenuInternet tree ────────────────────────────────────────────────
  WriteRegStr   HKCU "Software\Clients\StartMenuInternet\Lander Browser" \
                "" "Lander Browser"
  WriteRegStr   HKCU "Software\Clients\StartMenuInternet\Lander Browser\DefaultIcon" \
                "" "$INSTDIR\Lander Browser.exe,0"
  WriteRegStr   HKCU "Software\Clients\StartMenuInternet\Lander Browser\shell\open\command" \
                "" '"$INSTDIR\Lander Browser.exe"'
  WriteRegDWORD HKCU "Software\Clients\StartMenuInternet\Lander Browser\InstallInfo" \
                "IconsVisible" 1
  WriteRegStr   HKCU "Software\Clients\StartMenuInternet\Lander Browser\StartMenu" \
                "" "Lander Browser"

  ; ── Capabilities ─────────────────────────────────────────────────────────
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Lander Browser\Capabilities" \
              "ApplicationName" "Lander Browser"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Lander Browser\Capabilities" \
              "ApplicationIcon" "$INSTDIR\Lander Browser.exe,0"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Lander Browser\Capabilities" \
              "ApplicationDescription" "Privacy-first browser — built-in ad blocking, no tracking"

  ; URL associations
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Lander Browser\Capabilities\URLAssociations" \
              "ftp"   "LanderBrowserHTML"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Lander Browser\Capabilities\URLAssociations" \
              "http"  "LanderBrowserHTML"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Lander Browser\Capabilities\URLAssociations" \
              "https" "LanderBrowserHTML"

  ; File associations
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Lander Browser\Capabilities\FileAssociations" \
              ".htm"   "LanderBrowserHTML"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Lander Browser\Capabilities\FileAssociations" \
              ".html"  "LanderBrowserHTML"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Lander Browser\Capabilities\FileAssociations" \
              ".xhtml" "LanderBrowserHTML"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Lander Browser\Capabilities\FileAssociations" \
              ".pdf"   "LanderBrowserHTML"

  ; ── RegisteredApplications — what makes it appear in Default Apps UI ──────
  WriteRegStr HKCU "Software\RegisteredApplications" \
              "Lander Browser" \
              "Software\Clients\StartMenuInternet\Lander Browser\Capabilities"
!macroend

!macro customUnInstall
  ; Clean up all registry keys on uninstall
  DeleteRegKey  HKCU "Software\Classes\LanderBrowserHTML"
  DeleteRegKey  HKCU "Software\Clients\StartMenuInternet\Lander Browser"
  DeleteRegValue HKCU "Software\RegisteredApplications" "Lander Browser"
!macroend
