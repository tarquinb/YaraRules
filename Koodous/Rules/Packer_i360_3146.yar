rule Packer_i360
{
	meta:
		description = "i360"
		
    strings:
		$i360_1 = "libjiagu.so"
		$i360_2 = "libjiagu_art.so"

	condition:
        any of them 
}