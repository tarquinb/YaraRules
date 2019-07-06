import "androguard"

rule redalert2
{
	meta:
		author = "R"
		description = "https://clientsidedetection.com/new_android_trojan_targeting_over_60_banks_and_social_apps.html"

	strings:
		$intent = "HANDLE_COMMANDS"

	condition:
		$intent
}