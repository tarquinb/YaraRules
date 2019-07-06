import "androguard"

rule Chineseporn_3
{
	meta:
		description = "Detects few Chinese Porn apps"
		
	condition:
		(androguard.receiver(/lx\.Asver/) and
		 androguard.receiver(/lx\.Csver/))
		
}