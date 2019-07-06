rule PangXie
{
	meta:
		description = "PangXie"
		
    strings:
		$pangxie_1 = "libnsecure.so"

	condition:
        any of them 
}