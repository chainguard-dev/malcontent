rule matomo_filechecks: override {
  meta:
    description  = "Matomo core Filechecks.php - installation environment checks"
    php_executor = "medium"

  strings:
    $namespace = "namespace Piwik;"
    $class     = "class Filechecks"

  condition:
    filesize < 16KB and all of them
}

rule matomo_tracker: override {
  meta:
    description              = "Matomo PHP tracker library - analytics tracking API"
    tor_user                 = "low"
    hardcoded_ip_port        = "low"
    script_url_with_question = "low"

  strings:
    $class = "class MatomoTracker"
    $api   = "Matomo Tracking Web API"

  condition:
    filesize < 128KB and all of them
}

rule matomo_cpchart_data: override {
  meta:
    description = "c-pchart Data.php - charting library math expression evaluation"
    php_at_eval = "medium"

  strings:
    $namespace = "namespace CpChart;"
    $license   = "pchart.net/license"

  condition:
    filesize < 64KB and all of them
}

rule matomo_tcpdf_barcodes: override {
  meta:
    description                = "TCPDF barcode generation - character tables and FCS checksums"
    php_obfuscation            = "low"
    bidirectional_bitwise_math = "low"

  strings:
    $project = "This file is part of TCPDF software library"
    $file    = "tcpdf_barcodes_1d.php"

  condition:
    filesize < 128KB and all of them
}
