import "androguard"

rule Practica4

{
	meta:
		description = "Practica4-Slempo"
		sample = "7dab21d4920446027a3742b651e3ef8d"		

	strings:
	
		$a = "org/slempo/service" 
		$b = "http://185.62.188.32/app/remote/"
		$c = "http://185.62.188.32/app/remote/forms"
		$d = "org.slempo.service"
		
	condition:
		1 of them
	
}