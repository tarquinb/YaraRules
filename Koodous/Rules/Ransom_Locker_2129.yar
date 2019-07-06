rule Ransomware
{

strings:
	  $ = "SHA1-Digest: saH/Io6ET8Yni2QtswyVzLXkEIw="  //assets/empty.html
	  $ = "SHA1-Digest: 4gmxll2fP1i898eo90SddzFInVM="   //assets/form.html
	
	condition:
		all of them
}