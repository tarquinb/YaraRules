import "androguard"
import "file"
import "cuckoo"


rule walleteros
{
	meta:
		description = "Detects Bitcoin wallet.dat manipulation"

	strings:
		$a = "wallet.dat"

	condition:
		$a
		
}