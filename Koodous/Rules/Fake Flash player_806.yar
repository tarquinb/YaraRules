import "androguard"

rule FakeFlashPlayer
{
	meta:
		description = "Fake FlashPlayer apps"
	condition:
		androguard.app_name("Flash Player") or
		androguard.app_name("FlashPlayer") or
		androguard.app_name("Flash_Player") or
		androguard.app_name("Flash update")
}