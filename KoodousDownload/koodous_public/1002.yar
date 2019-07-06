import "androguard"
import "file"

rule testing
{
	meta:
		description = "This rule is a test"
		
	strings:
	  $a1 = "file.separator"
	  $a2 = "java.class.path"
	  $a3 = "java.class.version"
	  $a4 = "java.compiler"
	  $a5 = "java.ext.dirs"
	  $a6 = "java.home"
	  $a7 = "java.io.tmpdir"
	  $a8 = "java.library.path"
	  $a9 = "java.specification.name"
	  $a22 = "java.specification.vendor"
	  $a11 = "java.specification.version"
	  $a33 = "java.vendor"
	  $a44 = "java.vendor.url"
	  $a55 = "java.version"
	  $a66 = "java.vm.name"
	  $a77 = "java.vm.specification.name"
	  $a88 = "java.vm.specification.vendor"
	  $a99 = "java.vm.specification.version"
	  $a00 = "java.vm.vendor"
	  $a23 = "java.vm.version"
	  $a34 = "line.separator"
	  $a45 = "os.arch"
	  $a56 = "os.name"
	  $a78 = "os.version"
	  $a89 = "path.separator"
	  $a09 = "user.dir"
	  $a98 = "user.home"
	  $a87 = "user.name"
	  $b1 = "1xRTT"
	  $b2 = "CDMA"
	  $b3 = "EDGE"
	  $b4 = "eHRPD"
	  $b5 = "EDVO revision 0"
	  $b6 = "EDVO revision A"
	  $b7 = "EDVO revision B"
	  $b8 = "GPRS"
	  $b9 = "HSDPA"
	  $b11 = "HSPA"
	  $b12 = "HSPA+"
	  $b13 = "HSUPA"
	  $b14 = "iDen"
	  $b15 = "LTE"
	  $b16 = "UMTS"
	  $b17 = "CDMA"
	  $b18 = "GSM"
	  $b19 = "SIP"
	condition:
		all of them

		
}