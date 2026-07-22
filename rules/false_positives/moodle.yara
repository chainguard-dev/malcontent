rule moodle_graphlib: override {
  meta:
    description = "Moodle graphlib.php - legitimate graph rendering library"
    php_at_eval = "low"

  strings:
    $moodle_internal = "MOODLE_INTERNAL"
    $graphlib_desc   = "Graph Class. PHP Class to draw line, point, bar, and area graphs"

  condition:
    filesize < 100KB and all of them
}

rule moodle_tcpdf_barcodes: override {
  meta:
    description                    = "TCPDF barcode library bundled with Moodle"
    php_obfuscation                = "low"
    bidirectional_bitwise_math_php = "low"

  strings:
    $tcpdf_package = "com.tecnick.tcpdf"
    $tcpdf_author  = "Nicola Asuni - Tecnick.com LTD"

  condition:
    filesize < 90KB and all of them
}
