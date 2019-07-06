
import "androguard"


rule fake_market

{


    condition:

        androguard.package_name("com.minitorrent.kimill") 

}