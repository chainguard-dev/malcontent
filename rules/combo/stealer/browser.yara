
rule multiple_browser_credentials : suspicious {
  strings:
    $c_library_keychains = "/Library/Keychains"
    $c_cookies_sqlite = "cookies.sqlite"
    $c_moz_cookies = "moz_cookies"
    $c_opera_gx = "OperaGX"
    $c_keychain_db = "login.keychain-db"
    $c_dscl_local = "dscl /Local/Default"
    $c_osascript = "osascript"
    $c_find_generic_password = "find-generic-password"
    $not_security = "PROGRAM:security"
    $not_verbose = "system_verbose"
    $not_kandji = "com.kandji.profile.mdmprofile"
    $not_xul = "XUL_APP_FILE"
  condition:
    3 of ($c_*) and none of ($not_*)
}

rule multiple_browser_credentials_2 {
  strings:
    $a_google_chrome = "Google/Chrome"
    $a_app_support = "Application Support"
    $a_app_support_slash = "Application\\ Support"
    $a_cookies_sqlite = "cookies.sqlite"
    $a_cookies = "Cookies"
    $a_places_sqlite = "places.sqlite"
    $a_moz_cookies = "moz_cookies"
    $a_firefox_profiles = "Firefox/Profiles"
    $a_opera_gx = "OperaGX"
    $a_form_history = "formhistory.sqlite"
    $a_chrome_local_state = "Chrome/Local State"
    $a_brave_software = "BraveSoftware"
    $a_opera = "Opera Software"
    $not_osquery = "OSQUERY_WORKER"
    $not_private = "/System/Library/PrivateFrameworks/"
  condition:
    3 of ($a_*) and none of ($not_*)
}

rule multiple_browser_refs : notable {
  meta:
    description = "Uses HTTP, archives, and references multiple browsers"
  strings:
    $d_config = ".config" fullword
    $d_app_support = "Application Support" fullword
    $h_http = "http" fullword
    $h_POST = "POST" fullword
    $z_zip = "zip" fullword
    $z_ZIP = "ZIP" fullword
    $z_ditto = "ditto" fullword
    $z_tar = "tar" fullword
    $b_Yandex = "Yandex"
    $b_Brave = "Brave"
    $b_Firefox = "Firefox"
    $b_Safari = "Safari"
    $b_Chrome = "Chrome"
  condition:
    any of ($d*) and any of ($h*) and any of ($z*) and 2 of ($b*)
}
