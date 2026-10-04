rule moodle_graphlib: override {
  meta:
    description = "Moodle graphlib.php - legitimate graph rendering library"
    php_at_eval = "low"

  strings:
    $moodle_internal = /MOODLE_INTERNAL/
    $graphlib_desc   = /Graph Class\. PHP Class to draw line, point, bar, and area graphs/

  condition:
    filesize < 100KB and all of them
}

rule moodle_tcpdf_barcodes: override {
  meta:
    description                    = "TCPDF barcode library bundled with Moodle"
    php_obfuscation                = "low"
    bidirectional_bitwise_math_php = "low"

  strings:
    $tcpdf_package = /com\.tecnick\.tcpdf/
    $tcpdf_author  = /Nicola Asuni - Tecnick\.com LTD/

  condition:
    filesize < 90KB and all of them
}

rule moodle_adodb: override {
  meta:
    description                  = "ADOdb database abstraction library bundled with Moodle"
    php_suppressed_include       = "low"
    hardcoded_host_port_over_10k = "low"
    script_url_with_question     = "low"

  strings:
    $adodb_layer = /_ADODB_LAYER/
    $adodb_dir   = /ADODB_DIR/

  condition:
    filesize < 200KB and all of them
}

rule moodle_yui2_connection: override {
  meta:
    description = "YUI 2.9.0 connection modules bundled with Moodle"
    msxml2_http = "low"

  strings:
    $yui_connect = /YAHOO\.util\.Connect=\{_msxml_progid:/
    $yui_module  = /yui2-connection/
    $yui_version = /version: 2\.9\.0/

  condition:
    filesize < 20KB and $yui_connect and any of ($yui_module, $yui_version)
}
