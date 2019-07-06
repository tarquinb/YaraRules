import "androguard"

rule Bankyara
{
	meta:
		description = "Regla para detectar muestra de practica4"
		

	strings:
		$string_1 = "185.62.188.32"
	
	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.RECEIVE_SMS/) 
		
		}