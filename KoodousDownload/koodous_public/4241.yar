import "androguard"
import "file"
import "cuckoo"


rule ahmyth_rat
{
	meta:
		description = "This rule detects malicious spawns of Ahmyth RAT"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	condition:
		androguard.service(/ahmyth.mine.king.ahmyth.MainService/) and
		androguard.receiver(/ahmyth.mine.king.ahmyth.MyReceiver/)
		
}