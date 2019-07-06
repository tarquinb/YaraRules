import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "https://vms.drweb.com/virus/?_is=1&i=15503184"
		sample = ""

	strings:
		$a = "cf89490001"
		$b = "droi.zhanglin"
		$c = "configppgl"

	condition:
		$a or
		$b or
		$c
		
}