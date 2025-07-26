import "dotnet"
rule GhostShell_SharePoint
{
    meta:
        id = "3L2nePhWiYOjRbQGFIZjdc"
        fingerprint = "v1_sha256_f5b1a1f487e7af2f315825c0a6657a84088bbfcdf57f3523de14c36e608bf287"
        version = "1.0"
        date = "2025-07-25"
        modified = "2025-07-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies compiled Ghostfile.aspx, simple reverse shell / backdoor as also seen in the ToolShell (SharePoint) attacks."
        category = "TOOL"
        tool = "GHOSTSHELL"
        reference = "https://x.com/marius_benthin/status/1948761502334267478"
        hash = "7e9b77da1f51d03ee2f96bc976f6aeb781f801cf633862a4b8c356cbb555927d"

    strings:
        $aspx = ".aspx" ascii wide nocase

        $cmd_a = "Usage: ?cmd=command" ascii wide

        /*
        string text2 = string.Concat(new string[] { "c", "m", "d", ".", "exe" });
        string text3 = string.Join("", new string[] { "/c ", text });
        */
        $cmd_b = {7209000070A2110717720D000070A21107187211000070A21107197215000070A211071A7219000070A21107280C00000A0B7221000070188D1300000113071107167223000070A211071706A21107280D00000A}

        $layout_a = "/_layouts/" ascii wide nocase
        $layout_b = "/layouts/" ascii wide nocase


    condition:
        $aspx and any of ($cmd_*) and any of ($layout_*) or
        dotnet.guids[0]=="5497bdc1-57e4-4c5b-81eb-9dc7ca8b5aec" or
        dotnet.guids[0]=="cbcef74f-0a3d-4d87-8c6a-7044755c24f8"
}
