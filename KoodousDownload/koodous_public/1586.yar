rule packers : i360
{
	meta:
		description = "This rule detects packers based on files used by them"
		

	strings:
		
		$i360_1 = "libjiagu.so"
		$i360_2 = "libjiagu_art.so"
		
	condition:
		2 of them
		
}