import "androguard"
import "file"
import "cuckoo"


rule LeakerLocker
{
	meta:
		description = "This rule detects Leaker Locker samples"
		sample = "8a72124709dd0cd555f01effcbb42078"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/leakerlocker-mobile-ransomware-acts-without-encryption/"
		
	condition:
		androguard.receiver(/receiver.LockScreenReceiver/)
	
}