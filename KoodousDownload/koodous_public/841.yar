import "androguard"

rule BaDoink
{
		meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Virus de la Policia - android"
		sample = "9bc0fb0f05bbf25507104a4eb74e8066b194a8e6a57670957c0ad1af92189921"

	strings:
		$a = /asem\/[0-9a-zA-Z_\-\.]{0,32}\.apkPK/

	condition:
		$a
}