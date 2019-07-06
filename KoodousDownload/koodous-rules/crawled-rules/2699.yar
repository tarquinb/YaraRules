
import "androguard"

import "file"

import "cuckoo"



rule InjectionService

{

    meta:

        description = "This rule detects samples with possible malicious injection service"

        sample = "711f83ad0772ea2360eb77ae87b3bc45"



    condition:

        androguard.service(/injectionService/)



}