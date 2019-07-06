rule fakedomains
{
    strings:
		$ = "xn--pooniex-ojb.com"
		$ = "yazilim65.tk"
		$ = "xn--polonix-y8a.com"
		$ = "polonelx.com"
		$ = "po?oniex.com"
		$ = "xn--bittrx-th8b.com/"
		$ = { 70 6F C5 82 6F 6E 69 65 78 2E 63 6F 6D }
	
	condition:
		1 of them
}

//rule fakewallets
//{
//	strings:
//		$b0 = "poloniex" nocase
//		$b1 = "payeer" nocase
//		$b2 = "coinmarketcap" nocase
//		$b3 = "advcash" nocase
//		$b4 = "etherscan" nocase
//		$b5 = "binance" nocase
//		$b6 = "cryptoagentbot" nocase
//		$b7 = "BitPolyBot" nocase
//		
//		$a = "ENTER-YOUR-URL-HERE" nocase
//		
//	condition:
//		1 of ($b*) and $a
//}