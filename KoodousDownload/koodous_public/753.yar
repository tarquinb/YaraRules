rule pornplayer
{
	meta:
		description = "Porn Player, de.smarts.hysteric"

	strings:
		$a = "WLL.RSA"
		
	condition:
		$a
		
}