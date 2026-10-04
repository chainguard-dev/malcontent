rule rstudio_copilot_language_server: override {
  meta:
    description                  = "GitHub Copilot language server bundled with RStudio"
    find_generic_password        = "low"
    multiple_browser_credentials = "low"
    multiple_browser_refs        = "low"
    http_url_with_powershell     = "low"
    semicolon_relative_path_high = "low"

  strings:
    $copilot_lsp = /copilot-language-server/
    $gh_copilot  = /github\.copilot\.chat\.agent/

  condition:
    filesize < 15MB and all of them
}
