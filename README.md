# Master_Thesis

All the implementations in this repository constitute a first step towards providing "low-end" devices with post-quantum security. 


In this repository, one can find implementations of PICNIC and SPHINCS+ using the lightweight ciphers ASCON and SKINNY. 

Additionally, I implemented a successful attack against the SPHINCS+ scheme with a hypertree of size 28. Furthermore, in this attack, the higher the hypertree, the smaller the time difference between forging one or hundreds of signatures (maybe thousands :) ).

Results:

	-PICNIC: Applying either ASCON or SKINNY results in faster signatures than the original cipher but double the signature size.

	-SPHNICS+: ASCON provides faster signing speeds.

	-SPHINCS+ Attack: The time it takes to forge one signature for a hypertree of size 28 is five days.


