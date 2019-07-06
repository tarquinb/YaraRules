import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

 strings:
       $omegaSpyActivitiesPattern = /E:\x20activity\x20\(.+?\)\s+?A:\x20android:label.+?\s+?A:\x20android:name\([\dx]+?\)=("com\.android\.system\.MyLogin.+?"|"com\.android\.system\.AboutActivity"|"com\.android\.system\.HomeActitvity"|"com\.android\.system\.CreateAccountActivity"|"com\.android\.system\.MainActivity"|"com\.android\.system\.Splash"|"com\.android\.system\.Terms"|"com\.android\.system\.ConfigureActivity"|"com\.ispyoo\.common\..+?")/


   condition:
       $omegaSpyActivitiesPattern
		
}