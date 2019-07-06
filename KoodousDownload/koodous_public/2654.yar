import "androguard"
import "file"
import "cuckoo"


rule Target_FBMessenger : official
{
	strings:
		$string_target_fbmessenger = "com.facebook.orca"
	condition:

	($string_target_fbmessenger)
}