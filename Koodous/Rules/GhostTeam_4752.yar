import "androguard"

rule GhostTeam
{
	meta:
		description = "This rule will be able to tag all GhostTeam samples"
		hash_1 = "efca498b6a6715337cdedf627690217cef2d80d1c8f715b5c37652f556134f7e"
		hash_2 = "f3223010d0beace2445561bcb62ffaa491423cad0b94ca0c811a8e165b9b94a8"
		hash_3 = "f6feabac83250af4fe4eeaea508bf35da329c97d5f0c1a4b87c483f80ea40d50"
		reference_1 = "https://blog.trendmicro.com/trendlabs-security-intelligence/ghostteam-adware-can-steal-facebook-credentials/"
		reference_2 = "https://blog.avast.com/downloaders-on-google-play-spreading-malware-to-steal-facebook-login-details"
		author = "Jacob Soo Lead Re"
		date = "07-August-2018"
	condition:
		androguard.receiver(/.ScreenR/i)
		and androguard.receiver(/.BS/i) 
		and androguard.receiver(/.SR/i)
		and androguard.service(/.FS/i)
		and androguard.service(/.LS/i)
		and androguard.service(/.SO/i)
		and androguard.filter(/android.intent.action.BOOT_COMPLETED/i)
}