import "androguard"
import "file"
import "cuckoo"
import "droidbox"


rule koodous : official
{
	meta:
		description = "Ridiculous"
		sample = "https://koodous.com/apks?search=package_name:com.bnzve.qdcja https://koodous.com/apks?search=package_name:com.rebofjxojp.kpvhswsnwc"

	//strings:
		//$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}

	condition:
		droidbox.written.data("<string name=\"url\">http")
 
		
		
		
}