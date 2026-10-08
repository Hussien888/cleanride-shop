# CLEANRIDE Video Fix

Die Marketingvideos wurden für Browser-Kompatibilität neu encodiert:
- H.264 Main Profile + yuv420p + faststart (MP4)
- VP9 + yuv420p (WebM fallback)

Die Videos liegen zusätzlich unter `public/marketing/videos/`, damit sie beim Express/Render-Deployment tatsächlich ausgeliefert werden.
Die Standalone-`index.html` verwendet relative lokale Pfade.
