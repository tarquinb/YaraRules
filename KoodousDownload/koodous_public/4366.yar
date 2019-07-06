import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "remount system"

	strings:
		$a = "mount -o remount rw /system"

	condition:
		$a
		
}