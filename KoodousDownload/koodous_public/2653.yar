import "androguard"
import "file"
import "cuckoo"


rule Target_Facebook : official
{
	strings:
		$string_target_facebook = "com.facebook.katana"
	condition:

	($string_target_facebook)
}