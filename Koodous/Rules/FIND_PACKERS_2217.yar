import "androguard"
import "file"
import "cuckoo"

rule qihoo360 : packer
{
	meta:
		description = "Qihoo 360"

	strings:
		$a = "libprotectClass.so"
		
	condition:
		$a 
}

rule ijiami : packer
{
	meta:
		description = "Ijiami"
		
	strings:
		$old_dat = "assets/ijiami.dat"
		$new_ajm = "ijiami.ajm"
		$ijm_lib = "assets/ijm_lib/"
		
	condition:
		$old_dat or $new_ajm or $ijm_lib
}

rule naga : packer
{
	meta:
		description = "Naga"
		
	strings:
		$lib = "libddog.so"
		
	condition:
		 $lib
}


rule alibaba : packer
{
	meta:
		description = "Alibaba"
		
	strings:
		$lib = "libmobisec.so"
		
	condition:
		 $lib
}

rule medusa : packer
{
	meta:
		description = "Medusa"

	strings:
		$lib = "libmd.so"

	condition:
		$lib
}

rule baidu : packer
{
	meta:
		description = "Baidu"
		
	strings:
		$lib = "libbaiduprotect.so"
		$encrypted = "baiduprotect1.jar"
		
	condition:
		$lib or $encrypted
}

rule pangxie : packer
{
	meta:
		description = "PangXie"
	
	strings:
		$lib = "libnsecure.so"
		
	condition:
	 	$lib
}