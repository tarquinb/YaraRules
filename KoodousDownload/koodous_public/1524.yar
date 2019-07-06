import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$l = "android.intent.action.MULTI_CSC_CLEAR"
		$m = "lgeWapService.prov.persister.INSTALL_BROWSER"
		$k = "android.htc.intent.action.CUSTOMIZATION_CHANGE"

	condition:
		any of them
		
}