import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects coinhive domain in Apps"

	strings:
		$coinhive = "coinhive.com"
		$startmining = "startMining"

	condition:
		androguard.permission(/android.permission.INTERNET/) and
		($coinhive or $startmining)
}