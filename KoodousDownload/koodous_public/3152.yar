rule Alibaba
{
	meta:
		description = "Alibaba"
		
    strings:
		$ali_1 = "libmobisec.so"
		$ali_2 = "libmobisecy1.zip"
		$ali_3 = "mobisecenhance"
		$ali_4 = "StubApplication"

	condition:
        any of them 
}