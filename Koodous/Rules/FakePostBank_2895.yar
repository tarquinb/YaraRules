/*
 * Regla para detectar la ocurrencia de nuestra muestra 
 */
rule FakePostBank {
meta:
descripton= "Regla para Detectar Fake Post Bank"

strings:
		$a = "http://185.62.188.32/app/remote/"
		$b = "intercept_sms"
		$c = "unblock_all_numbers"
		$d = "unblock_numbers"
		$e = "TYPE_INTERCEPTED_INCOMING_SMS"
		$f = "TYPE_LISTENED_INCOMING_SMS"

	condition:
		$a and $b and ($c or $d or $e or $f)
}