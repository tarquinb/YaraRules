import "androguard"
import "file"

rule koodous : official
{
	meta:
		description = "This rule detects mazain application, used to show all Yara rules 						potential"
	
    strings:
        $str_1 = "com.bbva.bbvacontigo"
		$str_2 = "com.bbva.bbvawalletmx"
		$str_3 = "com.bbva.netcash"

    condition:
        all of ($str_*)
}