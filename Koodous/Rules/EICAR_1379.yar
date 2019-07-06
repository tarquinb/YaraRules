rule eicar
{
	meta:
		description = "EICAR-AV-Test"
		source = "http://www.eicar.org/86-0-Intended-use.html"

	strings:
		$eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii wide

	condition:
		$eicar
}