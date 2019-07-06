import "androguard"
import "file"
import "cuckoo"


rule Igexin
{
	meta:
		description = "igexin"
		thread_level = 3
		in_the_wild = true

	strings:

		$strings_a = "android.intent.action.GTDOWNLOAD_WAKEUP"

	

	condition:
		any of ($strings_*)
}