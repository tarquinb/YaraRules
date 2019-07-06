import "androguard"
import "file"
import "cuckoo"


rule BOI
{
	meta:
		description = "This rule detects the BOI applications, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$l = "com.bankofireland.mobilebanking"
		$m = "com.boi.tablet365"

	condition:
		any of them
		
}