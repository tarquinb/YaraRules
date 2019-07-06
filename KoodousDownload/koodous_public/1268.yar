import "androguard"
import "file"
import "cuckoo"


rule Igexin2252
{
	meta:
		description = "igexin2.2.2."
		thread_level = 3
		in_the_wild = true

	strings:

		$strings_a = "com.igexin.sdk.PushReceiver"
		$strings_b = "2.2.5.2"

	

	condition:
		any of ($strings_*)
}