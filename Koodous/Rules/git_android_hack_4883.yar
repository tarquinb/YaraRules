import "androguard"
import "file"
import "cuckoo"


rule git_android_hack
{
	meta:
		description = "This rule detects apps that claim to provide LIC branch details"
		sample = "111491fcdfa5871f617c42e259789b2f"

	strings:
		$a_1 = "Timer Running"
		$a_2 = "trying for socket"
		$a_3 = "no network stopping self"
		$a_4 = "getHistory"
		
		
		
	condition:
		all of ($a_*)
		
}