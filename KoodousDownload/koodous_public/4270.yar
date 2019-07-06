import "androguard"

rule lokibot_old
{
    strings:
		$a1 = "Seller" 
		$a2 = "Domian1" 
		
	condition:
        androguard.package_name(/compse.refact.st.upsssss/) and 
		1 of ($a*)
}