rule regla_practica
{
	meta:
		description = "PracticaC"
		sample = "7dab21d4920446027a3742b651e3ef8d"

	strings:
		$string_a = "3528-3589"
		$string_b = "/app/remote/forms/"
		$string_c = "IIII"
		$string_d = "slempo"
		
	condition:
		$string_a and $string_b and $string_c and $string_d
		}