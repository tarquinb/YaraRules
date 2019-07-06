
import "androguard"


rule Mulad

{

    meta:

        description = "Evidences of Mulad Adware via rixallab component"

    strings:

        $1 = "Lcom/rixallab/ads/" wide ascii


    condition:

        $1 or androguard.service(/com\.rixallab\.ads\./)

}