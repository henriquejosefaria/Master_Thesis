RUN_EXECUTABLE = make benchmark


all: sphincs+ picnic

sphincs+: run_sphincs_128 run_sphincs_64 run_modifyed_sphincs_128 run_modifyed_sphincs_64 run_modifyed_sphincs2_128 run_modifyed_sphincs2_64

sphincs+_128: run_sphincs_128 run_modifyed_sphincs_128

sphincs+_64: run_sphincs_64 run_modifyed_sphincs_64

picnic: run_picnic run_modifyed_picnic run_modifyed_picnic2

#
# SPHINCS+ MAKEFILES SCRIPT
#

run_sphincs_64:
	@echo "\n\n# --- Original SPHINCS+ (v. 64 bits) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+_64

run_sphincs_128:
	@clear
	@echo "# --- Original SPHINCS+ (v. 128 bits) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+_128

# ------------- #

run_modifyed_sphincs_64:
	@echo "\n\n# --- SPHINCS+ with ASCON-HASH (v. 64 bits) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+ascon_64
	@echo "\n\n"

run_modifyed_sphincs_64_short0:
	@echo "\n\n# --- SPHINCS+ with ASCON-HASH (v. 128 bits; h = 66; d = 22; w = 256; k = 33) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+ascon_128_h66_d_22_w256
	@echo "\n\n"

run_modifyed_sphincs_64_short1:
	@echo "\n\n# --- SPHINCS+ with ASCON-HASH (v. 128 bits; h = 44; d = 22; w = 16;  k = 33) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+ascon_128_h44_d22_w16
	@echo "\n\n"

run_modifyed_sphincs_64_short2:
	@echo "\n\n# --- SPHINCS+ with ASCON-HASH (v. 128 bits; h = 66; d = 22; w = 16;  k = 22) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+ascon_128_k22
	@echo "\n\n"

run_modifyed_sphincs_64_short3:
	@echo "\n\n# --- SPHINCS+ with ASCON-HASH (v. 128 bits; h = 33; d = 11; w = 16; k = 33) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+ascon_128_h33_d11_w16
	@echo "\n\n"

run_modifyed_sphincs_64_short1_1:
	@echo "\n\n# --- SPHINCS+ with ASCON-HASH (v. 128 bits; h = 44; d = 22; w = 256; k = 33) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+ascon_128_h44_d22_w256
	@echo "\n\n"

run_modifyed_sphincs_64_short2_1:
	@echo "\n\n# --- SPHINCS+ with ASCON-HASH (v. 128 bits; h = 66; d = 22; w = 256; k = 22) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+ascon_128_h66_d22_k22_w256
	@echo "\n\n"

run_modifyed_sphincs_64_short3_1:
	@echo "\n\n# --- SPHINCS+ with ASCON-HASH (v. 128 bits;  h = 33; d = 11; w = 256; k = 33) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+ascon_128_h33_d11_w256
	@echo "\n\n"

run_modifyed_sphincs_64_short4:
	@echo "\n\n# --- SPHINCS+ with ASCON-HASH (v. 128 bits; h = 66; d = 11; w = 256; k = 33) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+ascon_128_h66_d11_w256
	@echo "\n\n"

run_modifyed_sphincs_64_short4_1:
	@echo "\n\n# --- SPHINCS+ with ASCON-HASH (v. 128 bits; h = 55; d = 11; w = 256; k = 33) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+ascon_128_h55_d11_w256
	@echo "\n\n"

run_modifyed_sphincs_64_short4_2:
	@echo "\n\n# --- SPHINCS+ with ASCON-HASH (v. 128 bits; h = 44; d = 11; w = 256; k = 33) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+ascon_128_h44_d11_w256
	@echo "\n\n"


run_modifyed_sphincs_128:
	@echo "\n\n# --- SPHINCS+ with ASCON-HASH (v. 128 bits) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+ascon_128
	@echo "\n\n"

# ------------- #

run_modifyed_sphincs2_64:
	@echo "\n\n# --- SPHINCS+ with SKINNY-HASH (v. 64 bits) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+skinny_64
	@echo "\n\n"

run_modifyed_sphincs2_128:
	@echo "\n\n# --- SPHINCS+ with SKINNY-HASH (v. 128 bits) --- #\n"
	@time $(RUN_EXECUTABLE) -C sphincs+skinny_128
	@echo "\n\n"


#
# PICNIC MAKEFILES SCRIPT
#

run_picnic:
	@clear
	@echo "# --- Original PICNIC --- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full

run_modifyed_picnic:
	@echo "\n\n# --- PICNIC with SKINNY --- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full_skinny

run_modifyed_picnic2:
	@echo "\n\n# --- PICNIC with ASCON --- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full_ascon



.PHONY: all run_sphincs run_modifyed_sphincs run_picnic run_modifyed_picnic