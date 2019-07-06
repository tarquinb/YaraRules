import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

   strings:
       $serialVersionUID_Pattern = /Static\x20fields\x20{5}-\n(.+\n)+\x20{6}name\x20{10}:\x20'serialVersionUID'\n(.+\n)+\x20{6}value\x20{9}:\x20(0x0FC14E688B5377|0x09D8D10157142AE|0x37214C0A1F2548FF|0x559DB3549F77E491|-0x7014E03F2146082D|-0x0A537930CCB2EDD0)/


   condition:
       $serialVersionUID_Pattern  
		
}