rule gdown_vendored_ytdlp_cookies: override {
  meta:
    description                  = "gdown/_vendor/_ytdlp_cookies.py, the vendored yt-dlp browser cookie reader, and its .pyc"
    chromium_master_password     = "medium"
    macos_cookies                = "medium"
    firefox_cookies              = "medium"
    find_generic_password        = "medium"
    multiple_browser_credentials = "medium"
    multiple_browser_refs        = "medium"

  strings:
    $ytdlp_shim           = /_ytdlp_shim/
    $secretstorage_reason = /_SECRETSTORAGE_UNAVAILABLE_REASON/
    $extract_cookies      = /extract_cookies_from_browser/

  condition:
    filesize < 128KB and all of them
}
