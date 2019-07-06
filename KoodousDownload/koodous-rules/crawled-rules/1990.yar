
import "androguard"


rule koodous : official

{

    meta:

        description = "looking for root exploit"

        sample = "16de78a5bbd91255546bfbb3565fdbe4c9898a16062c87dbb1cf24665830bbe"


    strings:

                $1 = "Get Root success"

                $2 = "libhxy"

                $3 = "libxy_arm64.so"

                $4 = "firewall"

                $5 = "busybox"

    condition:

                all of ($*)



}


rule construct : official

{

    meta:

        description = "looking for root exploit - constructeur"

        sample = "16de78a5bbd91255546bfbb3565fdbe4c9898a16062c87dbb1cf24665830bbe"


    strings:

                $_1 = "asus"

                $_2 = "huawei"

                $_3 = "zte"

                $_4 = "htc"

                $_5 = "sonyericsson"

    condition:

                all of ($_*)



}