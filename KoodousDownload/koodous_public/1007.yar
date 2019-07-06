import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "8907e44c44753482ca1dd346c8282ae546a554c210dd576a3b1b467c25994c0a"

	strings:
	  $mrat_domain = "fdddt.pw"


	condition:
		$mrat_domain
		
}