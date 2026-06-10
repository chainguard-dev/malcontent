rule code_server_copilot: override {
  meta:
    description                  = "code-server bundled GitHub Copilot Chat extension"
    http_url_with_powershell     = "low"
    semicolon_relative_path_high = "low"
    high_fetch_command_val       = "low"

  strings:
    $copilot_chat = "copilot-chat"
    $vscode_repo  = "github.com/microsoft/vscode-copilot-chat"
    $dotnet       = "dotnet/install-scripts/main/src/dotnet-install"

  condition:
    filesize < 500KB and $copilot_chat and any of ($vscode_repo, $dotnet)
}
