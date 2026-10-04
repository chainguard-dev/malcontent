rule xlsx_populate_browser: override {
  meta:
    description                  = "xlsx-populate/browser/xlsx-populate.min.js"
    base64_zip                   = "low"
    unsigned_bitwise_math        = "low"
    unsigned_bitwise_math_excess = "low"
    js_eval                      = "low"
    js_eval_obfuscated_fromChar  = "low"
    js_eval_near_enough_fromChar = "low"

  strings:
    $global      = /XlsxPopulate/
    $visible_msg = /workbook must contain at least one visible sheet/
    $package     = /xlsx-populate/

  condition:
    filesize < 1MB and $global and any of ($visible_msg, $package)
}
