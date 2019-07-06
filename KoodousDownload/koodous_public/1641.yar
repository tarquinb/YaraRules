rule PornSlocker
{
	meta:
		description = "This rule detects some common used pictures or other files in SLocker / PornLocker variants"

strings:
	  $ = "SHA1-Digest: 7IsBe9rxRK/MPmdDkVLoGDUgc9U="
	  $ = "SHA1-Digest: MVIz+0h8/7uJg6FzxezlLYeQ8DI="
	  $ = "SHA1-Digest: QmH6OE16ItwdO6nLHXdCYYsWZlw="
	  $ = "SHA1-Digest: krfyZeqOcVdXKp14LSPboF/qBAM="
	  $ = "SHA1-Digest: oKndfTj8AicZPlKCRIHBVbAAz2Y="
	  $ = "SHA1-Digest: LbMVl56xHfaJYHRPTu4qeKfQJQQ="
	  $ = "SHA1-Digest: VmDAQ7bv9tQkB5FHW886FsgadFQ="
      $ = "SHA1-Digest: kQM7/tmBPdTILxiwYuvQvwwPAfo="
	  $ = "SHA1-Digest: lOoGSYGEUN3eTMcSPE3iNX7lw4Q="
	  $ = "SHA1-Digest: cPVeLhm/BlUOhKZRfUx8WGvyT90="
      $ = "SHA1-Digest: v4/pYdRCXHZraLWFGWENv0ie1vk="
      $ = "SHA1-Digest: zoYgXzxdaIJIyoslwVSC/IlxAtw="
	  $ = "SHA1-Digest: xA5tmmIrL9ex9WSLmPHtmDXiamc="
	  $ = "SHA1-Digest: sOkywP18/kCq9tn0nZ4JywzaWno="
	  $ = "SHA1-Digest: PXi8kScvGYUTpnMFZDl5S62ZM8k="
	  $ = "SHA1-Digest: PcP6KWHRgXLam8J5uO6lRxuBvPc="
	  $ = "SHA1-Digest: J0lAOGynBbj50bZ/VRkk2vx9Ysc="
	  $ = "SHA1-Digest: Kb+VcnqOoUdfJkW7ZMhXoJADQQ0="
      $ = "SHA1-Digest: sBLBhcd7IpCFfuuLRAuBOzOQ4J4="
     
	
	condition:
		2 of them
}