import "androguard"



rule koodous : official
{
	meta:
		description = "Refering to background site so captchas get solved"

	strings:
		$a = "http://antigate.com/in.php"
		$b = "http://antigate.com/"
	condition:
		$a or 
		$b
		
}