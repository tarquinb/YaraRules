rule YARA_Act4_DG

{
	meta:
		description = "Esta regla detecta Malware de Postbank FinanzAssistent"

	strings:
		$a = "#intercept_sms_start" wide ascii
		$b = "#intercept_sms_stop" wide ascii
		$c = "Lorg/slempo/service/Main" wide ascii
		$d = "Lorg/slempo/service/a/" wide ascii
		$e = "com.slempo.service.activities" wide ascii
		$f = /com.slempo.service/ nocase
		
		

	condition:
		$c and ($a or $b or $d or $e or $f)
		}