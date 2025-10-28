rule EE_Loader
{
    meta:
        id = "3cE9Nc9q8mf33jLJj2u2gN"
        fingerprint = "v1_sha256_8a1f1f3aecfd55da0597ee08795122dbdbea7ad6902b638b8d6e1b73d8ccd5fb"
        version = "1.0"
        date = "2025-10-27"
        modified = "2025-10-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies loader used by Earth Estries."
        category = "MALWARE"
        hash = "5e062fee5b8ff41b7dd0824f0b93467359ad849ecf47312e62c9501b4096ccda"

	strings:
			/*
            pFVar7 = GetProcAddress(pHVar3,(LPCSTR)&local_20);
            if (pFVar7 != (FARPROC)0x0) {
              local_6c = 0x2e534552;
              local_68 = 0x4352;
              local_118c.X = 0;
              local_118c.Y = 0;
              uVar8 = (*local_1194)(0xfffffff5);
              CVar4 = local_118c;
			*/
			$load = { c7 4? ?? 52 45 53 2e 6a f5 c7 4? ?? 52 43 00 00 89 8? ?? ?? ?? ??  } //RES.RC
    
	condition:
		all of them
}	
