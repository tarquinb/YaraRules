
import "androguard"



rule protank_url : adware

{

    meta:

        description = ""

        sample = ""


    condition:

        androguard.url(/pro-tank-t34\.ru/) 


}


rule protank_package_name : adware

{

    meta:

        description = ""

        sample = ""


    condition:

        androguard.app_name("PlayMob Market")


}