rule simplelocker_b_tor
{
	meta:
		description = "SimpleLocker.B Tor enabled"

	strings:
		$a = "1372587162_chto-takoe-root-prava.jpg"
		$b = "libtor.so"
		
	condition:
		$a and $b
}