rule Ransomware
{
	strings:
		$a = "All your files are encrypted"
		$b = "Your phone is locked until payment"

	condition:
		$a or $b	
}