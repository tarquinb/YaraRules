rule Naga
{
	meta:
		description = "Naga"
		
    strings:
		$naga_1 = "libddog.so"

	condition:
        any of them 
}