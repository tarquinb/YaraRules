/*
 * Regla para detectar la ocurrencia de nuestra muestra 
 */
rule FakePostBank {
meta:
descripton= "Regla para Detectar Fake Post Bank"
thread_level=3

strings:
	$a = "Lorg/slempo/service/Main;" wide ascii
	$b = "http://185.62.188.32/app/remote/" wide ascii
	$c = "&http://185.62.188.32/app/remote/forms/" wide ascii
	

condition:
	// The condition to match
	$a or $b or $c 
}