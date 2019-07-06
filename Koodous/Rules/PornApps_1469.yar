import "androguard"
import "file"
import "cuckoo"


rule PornApps
{
	meta:
		description = "Rule to detect certain Porn related apps"
		sample = "baea1377a3d6ea1800a0482c4c0c4d8cf50d22408dcf4694796ddab9b011ea14"
		
	strings:
		$a = "/system/bin/vold"
	
			
	condition:
		(androguard.activity(/.HejuActivity/) and $a)or
		androguard.service(/\.cn\.soor\.qlqz\.bfmxaw\.a\.a\.c\.d/)
}