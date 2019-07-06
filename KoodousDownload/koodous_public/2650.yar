import "androguard"
import "file"
import "cuckoo"


rule Target_Bank_CA : official
{
	strings:
		$string_target_bank_ca = "fr.creditagricole.androidapp"
	condition:

	($string_target_bank_ca)
}