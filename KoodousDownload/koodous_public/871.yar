import "androguard"


rule infoLeak
{
	meta:
		description = "Get user info (IP, IMEI, SMS...) sent to remote address. "
		

	strings:
		$a = "http://imgsx.lingte.cc:8080/MTProject/MTContr?action=MTDetial&id="
		$b = "http://count.lingte.cc/IsInterface.php"
		$c = "http://imgsx.lingte.cc:8080/MTProject/MTContr?action=MTListUp&typeid="


	condition:
		$a or $b or $c
		
}