rule snipe_it_storage_helper: override {
  meta:
    description                         = "app/Helpers/StorageHelper.php CSV formula sanitizer"
    SEKOIA_Technique_Csv_Dde_Exec_Regex = "harmless"

  strings:
    $csv_escape = /League\\Csv\\EscapeFormula/
    $class      = /class StorageHelper/

  condition:
    filesize < 16KB and all of them
}

rule snipe_it_csv_sanitize_test: override {
  meta:
    description                         = "tests/Unit/Helpers/StorageHelperCsvSanitizeTest.php"
    SEKOIA_Technique_Csv_Dde_Exec_Regex = "harmless"

  strings:
    $class = /class StorageHelperCsvSanitizeTest extends TestCase/
    $sut   = /StorageHelper::downloader/

  condition:
    filesize < 8KB and all of them
}

rule snipe_it_upload_extension_rule: override {
  meta:
    description                             = "app/Rules/AllowedUploadExtension.php upload validator"
    SIGNATURE_BASE_WEBSHELL_PHP_Dynamic_Big = "harmless"

  strings:
    $class     = /class AllowedUploadExtension implements ValidationRule/
    $php_guard = /phpExecutableExtensions/

  condition:
    filesize < 8KB and all of them
}

rule snipe_it_upload_extension_test: override {
  meta:
    description      = "tests/Unit/Rules/AllowedUploadExtensionTest.php webshell upload fixtures"
    php_bin_hashbang = "harmless"
    php_remote_exec  = "harmless"

  strings:
    $class = /class AllowedUploadExtensionTest extends TestCase/
    $rule  = /App\\Rules\\AllowedUploadExtension/

  condition:
    filesize < 12KB and all of them
}
