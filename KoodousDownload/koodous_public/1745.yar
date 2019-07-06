import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "identify samples that check if root"


	strings:
		$isroot = "uid=0"

	condition:
		$isroot
		
}