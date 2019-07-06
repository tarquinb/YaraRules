import "androguard"

rule wefleet
{

	strings:
		$a = "wefleet.net/smstracker/ads.php" nocase

	condition:
		$a
		
}