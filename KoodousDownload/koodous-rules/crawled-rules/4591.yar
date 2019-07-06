
import "androguard"

import "file"

import "cuckoo"



rule ru_samples

{

    meta:

        description = "This rule detects ru.android samples"

        sample = "1a45053463dee0c35ea67c0de177040c"


    condition:

        androguard.activity("/ru.android.top.LoaderActivity/") and

        androguard.activity("/ru.android.top.RuleActivity/")


}