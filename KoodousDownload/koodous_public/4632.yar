import "androguard"
import "file"
import "cuckoo"

import "androguard"
import "file"
import "cuckoo"

rule chornclickers : packer
{

  meta:
    description = "Custom Chinese 'ChornClickers'"
    url         = "https://github.com/rednaga/APKiD/issues/93"
    example     = "0c4a26d6b27986775c9c58813407a737657294579b6fd37618b0396d90d3efc3"

  strings:
    $a = "libhdus.so"
    $b = "libwjus.so"

  condition:
    all of them
}