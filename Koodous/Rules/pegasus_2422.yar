import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "pegasus"
	strings:
		$a = "coldboot_init"
		$b = "/csk"

	condition:
		$a and $b
		
}