import "androguard"



rule slempo : package
{
	meta:
		description = "This rule detects the slempo (slembunk) variant malwares by using package name and app name comparison"
		sample = "24c95bbafaccc6faa3813e9b7f28facba7445d64a9aa759d0a1f87aa252e8345"

	condition:
		androguard.package_name("org.slempo.service")
		}