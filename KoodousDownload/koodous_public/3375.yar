import "androguard"
import "file"
import "cuckoo"

/*
https://blog.lookout.com/sonicspy-spyware-threat-technical-research

I consider "dt7C1uP3c2al6l0ib" is special and found thz:

https://www.hybrid-analysis.com/sample/7b036f9e0fd5f750dc27b60c421159f77bffd45ca59ac54c154ab7b106cceff6?environmentId=100&lang=ms
https://malwr.com/analysis/NTFhN2VhNjY1N2FkNGFiMWFjOTBjYTZlMjI4YWViODA/

also can check "not concteed", consider the author's language habit.

other c&c:
arshad93.ddns.net     208.73.202.116
manatwork.no-ip.biz     79.34.193.17
hamo55.hopto.org     197.39.120.138
andoo.ddns.net          45.244.104.143
andoo.ddns.net      45.244.104.143

port:
2222,  1337, 1333
*/
rule VT_Sonicspy : Spy
{
	meta:
		detail = "https://blog.lookout.com/sonicspy-spyware-threat-technical-research"

	strings:
		$ = "dt7C1uP3c2al6l0ib"
		$ = "not concteed"


	condition:
		all of them
}