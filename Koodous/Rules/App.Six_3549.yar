import "androguard"

rule appsix
{
    strings:
		$a1 = "cvc_visa" 
		$a2 = "controller.php"  
		$a3 = "mastercard" 
	condition:
        androguard.package_name(/app.six/) and 
		2 of ($a*)
}