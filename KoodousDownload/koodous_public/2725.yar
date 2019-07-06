import "androguard"
import "file"
import "cuckoo"


rule Want2Badmin
{
	meta:
		description = "Apps that want to be admins through intents"

	strings:
		$a = "android.app.extra.DEVICE_ADMIN" nocase
		$b = "ADD_DEVICE_ADMIN" nocase
		$c = "DEVICE_ADMIN_ENABLED"

	condition:
		$a or $b or $c
		
}