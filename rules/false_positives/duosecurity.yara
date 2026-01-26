rule duosecurity_universal_php: override {
  meta:
    description           = "duo_universal_php - Duo Security 2FA client library"
    php_urlvar_recon_exec = "low"

  strings:
    $namespace  = "namespace Duo\\DuoUniversal"
    $user_agent = "duo_universal_php/"
    $license    = "https://opensource.org/licenses/BSD-3-Clause"
    $curl_exec  = "curl_exec("

  condition:
    filesize < 64KB and all of them
}
