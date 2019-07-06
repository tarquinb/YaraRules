
import "androguard"



rule spynote: RAT

{

    meta:

        sample = "bd3269ec0d8e0fc2fbb8f01584a7f5de320a49dfb6a8cc60119ad00c7c0356a5"



    condition:

        androguard.package_name("com.spynote.software.stubspynote")

}