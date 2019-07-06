rule Finsky {
	meta:
	sample = "f10ff63c0a8b7a102d6ff8b4e4638edb8512f772,a5b9ca61c2c5a3b283ad56c61497df155d47f276"
	description = "http://vms.drweb.ru/virus/?_is=1&i=14891022"
		
	strings:
		$hooker1 = "hooker.dex"
		$hooker2 = "hooker.so"
		
		$wzh = "wzhtest1987"
		
		$finsky = "finsky"
		
		$cc = "api.sgccrsapi.com"
		
	condition:
		1 of ($hooker*) and ($cc or $wzh) and $finsky
		
}