rule lokibot_grotez
{
	meta:
		description = "This rule detects the Loki iterration application, used to show all Yara rules potential"

	strings:
		$a = "certificato37232.xyz"
		$b = "47.91.77.112"

	condition:
		any of them
		
}