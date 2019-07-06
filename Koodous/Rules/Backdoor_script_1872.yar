import "androguard"


rule koodous : official
{
	meta:
		description = "Detects samples repackaged by backdoor-apk shell script"
		Reference = "https://github.com/dana-at-cp/backdoor-apk"
		
	strings:
		$str_1 = "cnlybnq.qrk" // encrypted string "payload.dex"

	condition:
		$str_1 and 
		androguard.receiver(/\.AppBoot$/)		
}