rule packers : tencent
{
	meta:
		description = "This rule detects packers based on files used by them"
		

	strings:
		$tencent_1 = "libmain.so"
		$tencent_2 = "libshell.so"

	condition:
		2 of them
		
}