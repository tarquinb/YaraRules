import "androguard"

rule urls
{
	meta:
		description = "Lukas Stefanko https://twitter.com/LukasStefanko/status/877842943142281216"

	strings:
		$ = "0s.nrxwo2lo.ozvs4y3pnu.cmle.ru"
		$ = "0s.nu.ozvs4y3pnu.cmle.ru"
		$ = "0s.nu.n5vs44tv.cmle.ru"
		$ = "navidtwobottt.000webhostapp.com/rat/upload_file.php"
		$ = "telememberapp.ir/rat/upload_file.php"

	condition:
		1 of them
		
}