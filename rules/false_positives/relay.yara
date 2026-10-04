rule sentry_relay: override {
  meta:
    description               = "Sentry Relay: user-agent pattern comments carry device-profile IP URLs"
    http_hardcoded_ip_dev_shm = "low"

  strings:
    $sentry_relay     = /sentry\.relay\//
    $relay_server     = /relay_server::services::/
    $ua_normalization = /relay-event-normalization\/src\/normalize\/user_agent\.rs/

  condition:
    filesize < 75MB and all of them
}
