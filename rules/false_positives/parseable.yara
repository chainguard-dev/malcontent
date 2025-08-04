rule public_webhook: override {
  meta:
    description                                                          = "/usr/bin/parseable"
    DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_References_Publicserviceinterface = "medium"

  strings:
    $parseable = "parseable"
    $test      = "\"endpoint\":\"https://webhook.site/8e1f26bd-2f5b-47a2-9d0b-3b3dabb30710\",\"name\":\"Test Webhook\""

  condition:
    $parseable and $test
}
