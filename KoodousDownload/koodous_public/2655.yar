import "androguard"
import "file"
import "cuckoo"


rule Target_Instagram : official
{
	strings:
		$string_target_fbmessenger = "com.instagram.android"
	condition:

	($string_target_fbmessenger)
}