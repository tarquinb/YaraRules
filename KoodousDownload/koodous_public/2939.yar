import "androguard"


rule slempo : practica
{
	meta:
		description = "Regla para detectar el malware slempo."

	strings:
		$a = "org.slempo"
		$b = "com.slempo"
		$c = "org/slempo"
		$d = "intercept_sms_start"
		$e = "wipe_data"
		$f = "intercept_sms_stop"

	condition:
		androguard.package_name("org.slempo.service") or
		
		$a or $b or $c or ($d and $e and $f)
		
		
}