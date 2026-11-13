# Ta3alm Platform — Legacy YouTube to Protected Streaming Migration Plan

## 1. Objective
Systematically migrate platform-owned lecture videos currently stored as YouTube URLs in `teachers.models.Lecture.video_link` to private HLS/DASH streaming infrastructure backed by `api_v1.models.VideoAsset`, without breaking ongoing student classes or violating YouTube Terms of Service.

---

## 2. Hosting & DRM Comparison for Ta3alm

| Option | Transcoding & ABR HLS | Signed Playback URLs | Hardware DRM (Widevine/FairPlay) | Egyptian / MENA Latency | Verdict |
|---|---|---|---|---|---|
| **Bunny Stream** (Recommended Cost/Perf) | Automatic multi-bitrate HLS (`360p`–`1080p`) + WebVTT captions | Built-in SHA-256 directory token auth (supported in `_sign_bunny_stream_url`) | MediaCage Enterprise DRM available | Excellent CDN edge PoPs | **Best initial fit for price-sensitive growth** |
| **Cloudflare Stream** | Automatic ABR HLS/DASH + thumbnails | Built-in RS256/JWK signed tokens (supported in `_sign_cloudflare_stream_url`) | Enterprise DRM add-on | Strong global edge | **Best serverless developer UX** |
| **AWS S3 + MediaConvert + CloudFront** | Full control over CMAF HLS + DASH + AES-128 / SPEKE DRM | CloudFront RSA signed cookies/URLs (`CDN_SIGNING_SECRET` / RSA) | Full Multi-DRM via SPEKE (Widevine, FairPlay, PlayReady) | High control, higher ops complexity | **Best at massive scale or strict Widevine L1 mandate** |

*Note:* The Django `video_security.py` provider adapter already implements signed token generation hooks for **Cloudflare Stream**, **Bunny Stream**, **HMAC CDN URLs**, and an authenticated **internal private proxy** (`/api/v1/videos/stream/<playback_token>/`).

---

## 3. Phased Migration Strategy

### Phase 1: Inventory & Tagging (Zero Downtime)
1. Run Django database migrations to create `api_v1.VideoAsset` and companion tables:
   ```bash
   python manage.py migrate
   ```
2. Audit all existing lectures and create baseline tracking rows:
   ```bash
   python manage.py audit_video_migration --create-placeholders
   ```
3. All unmigrated YouTube lectures receive `migration_status='legacy_youtube'` and continue to open cleanly via `_LegacyYoutubeSeparatedCard` (compliant external handoff) on mobile and existing embeds on web until their source master MP4s are uploaded.

### Phase 2: Teacher Master Video Upload & Transcoding Pipeline
1. Teachers or platform operations upload original `.mp4` / `.mov` source files into a private ingest bucket (Cloudflare Stream Direct Creator Upload or Bunny Stream API) — **never** ripping unauthorized third-party YouTube channels.
2. Webhook or background worker polls transcoding completion (`queued` -> `transcoding` -> `migrated`), populates `VideoAsset`:
   - `source_type = 'hls_protected'` (or `'cloudflare_stream'` / `'bunny_stream'`)
   - `provider_asset_id = <provider-video-uid>`
   - `manifest_url = <private master .m3u8>`
   - `quality_variants` (`360p`, `480p`, `720p`, `1080p`)
   - `subtitle_tracks` (`.vtt` captions)
   - `duration_seconds`
3. Mark `VideoAsset.migration_status = 'verified'` after QA playback check on a real Android device.

### Phase 3: Web Template Alignment & Legacy Retirement
1. Update `templates/includes/custom_video_player.html` on Django web to render an authenticated HLS.js player when `lecture.video_asset.is_native_protected` is `True`.
2. Archive `Lecture.video_link` raw URLs for migrated lectures or restrict them to admin auditing only.
3. Enforce a cutoff date after which newly created lectures in Teacher Dashboard upload directly to protected HLS hosting rather than accepting external YouTube links.

