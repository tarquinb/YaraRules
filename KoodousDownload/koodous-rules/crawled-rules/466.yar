
import "cuckoo"


rule adecosystems

{

    condition:

        cuckoo.network.http_request(/ads01\.adecosystems\.com/) or cuckoo.network.http_request(/ads02\.adecosystems\.com/) or cuckoo.network.http_request(/ads03\.adecosystems\.com/) or cuckoo.network.http_request(/ads04\.adecosystems\.com/)

}