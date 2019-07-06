rule oie_transparent
{
	meta:
	description = "may produce false positive, we will see"
	
	strings:
		$a = "oie_transparent_1.png"

	condition:
		$a
	
}

rule Ransomware
{

strings:
	  $ = "SHA1-Digest: saH/Io6ET8Yni2QtswyVzLXkEIw="  //assets/empty.html
	  $ = "SHA1-Digest: 4gmxll2fP1i898eo90SddzFInVM="   //assets/form.html
	
	condition:
		all of them
}