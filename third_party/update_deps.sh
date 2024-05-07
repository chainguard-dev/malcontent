#!/bin/sh
# re-pin a third_party dependency to the latest code

update_dep() {

}

sync_to_head() {


}

sync_to_release() {
    
}



.PHONY: update-yaraforge
update-yaraforge:
	mkdir -p out
	curl -sL -o out/yaraforge.zip https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip
	unzip -o -j out/yaraforge.zip packages/full/yara-rules-full.yar -d rules/third_party/

.PHONY: update-huntress
update-huntress:
	rm -Rf out/huntress  rules/third_party/huntress
	mkdir -p out rules/third_party/huntress
	git clone https://github.com/huntresslabs/threat-intel.git out/huntress
	find out/huntress \( -name "*.yar*" -o -name "*LICENSE*" \) -print -exec cp {} rules/third_party/huntress/ \;
	perl -p -i -e 's#"/Library/Application Support/Google/Chrome/Default/History"#/\\/Library\\/Application Support\\/Google\\/Chrome\\/Default\\/History\/#' rules/third_party/huntress/lightspy.yara
	set -e ;\
	cd out/huntress ;\
	COMMIT=$$(git rev-parse head) ;\
	echo $$COMMIT > ../../rules/third_party/huntress/COMMIT ;\
	echo "to commit update, use:" ;\
	echo "git commit rules/huntress -m \"update huntress threat-intel to latest - $$COMMIT\""

.PHONY: update-threathunting-keywords
update-threathunting-keywords:
	@current_sha=a21391e7280a4347dd7faebd7b5f54344b484ec7; \
	upstream_sha=$$(curl -s https://api.github.com/repos/mthcht/ThreatHunting-Keywords-yara-rules/commits/main | grep sha | head -n 1 | cut -d '"' -f 4); \
	if [ "$$current_sha" != "$$upstream_sha" ]; then \
		echo -e "ThreatHunting-Keywords-yara-rules has been updated to $$upstream_sha.\nPlease update the current_sha in the Makefile."; \
	else \
		echo "ThreatHunting-Keywords-yara-rules is up to date."; \
	fi; \
	curl -sL -o rules/third_party/mthcht_thk_yara_rules.yar https://raw.githubusercontent.com/mthcht/ThreatHunting-Keywords-yara-rules/$$current_sha/yara_rules/all.yara
# rewrite Chrome extension ID's to avoid XProtect matching bincapz
	perl -p -i -e 's#\/([a-z]{31})([a-z])\/#\/$$1\[$$2\]\/#;' rules/third_party/mthcht_thk_yara_rules.yar
