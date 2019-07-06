import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects malicious apps with DroidJack components"
		sample = "51b1872a8e2257c660e4f5b46412cb38"

	condition:
		androguard.package_name("net.droidjack.server") and
		androguard.service(/net\.droidjack\.server\./)
		
		
}