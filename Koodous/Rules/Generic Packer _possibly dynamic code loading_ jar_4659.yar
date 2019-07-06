import "androguard"
import "file"
import "cuckoo"



rule could_be_packer : packer
{
    meta:
        description = "Generic Packer"

    strings:
        $a = /assets\/.{1,128}\.jar/
        $b = /assets\/[A-Za-z0-9.]{2,50}\.jar/
		
		$zip_head = "PK"
        $manifest = "AndroidManifest.xml"

    condition:
        ($a or $b) and
		($zip_head at 0 and $manifest and #manifest >= 2)
}