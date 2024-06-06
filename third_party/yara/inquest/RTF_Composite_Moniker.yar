rule RTF_Composite_Moniker
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects an attempt to exploit the CVE-2017-8570 vulnerability. A remote code execution vulnerability exists in Microsoft Office software when it fails to properly handle objects in memory. An attacker who successfully exploited the vulnerability could use a specially crafted file to perform actions in the security context of the current user."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Labs Empirical Observations"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "bbec59b5557a9836306dd487294bac62227be2f0e7b56c3aeccd6415bfff82a6"

	strings:
			$magic_rtf = "{\\rt" nocase
        $st1 = "0903000000000000C000000000000046" nocase // Composite Moniker
        $st2 = "0303000000000000C000000000000046" nocase // File Moniker
        $st3 = "C6AFABEC197FD211978E0000F8757E2A" nocase // "new" Moniker
        $st4 = "01004F006C0065" nocase // "\x01Ole"
	condition:
			$magic_rtf at 0 and all of ( $st* )
}