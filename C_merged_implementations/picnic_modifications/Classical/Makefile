RUN_EXECUTABLE = make benchmark


all: picnic picnic_chain

picnic: run_original run_picnic run_picnic_SKINNY_HASH run_picnic_FULL_SKINNY run_picnic_ASCON_HASH run_picnic_FULL_ASCON

picnic_chain: run_picnic_chain run_picnic_SKINNY_HASH_chain run_picnic_FULL_SKINNY_chain run_picnic_ASCON_HASH_chain run_picnic_FULL_ASCON_chain

#
# PICNIC MAKEFILES SCRIPT
#


run_original:
	@clear
	@echo "#######################################################\n\n# ------------  Original PICNIC NO WOTS+ ------------ #\n\n#######################################################\n\n# ---------- Original PICNIC WITHOUT WOTS+ ---------- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full_original


run_picnic:
	@echo "\n\n\n#####################################################\n\n# ---------- PICNIC FREE ROUNDS VERSIONS ---------- #\n\n#####################################################\n\n# --------- Original PICNIC WITH SHAKE256 --------- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full

run_picnic_SKINNY_HASH:
	@echo "\n\n# ------------ PICNIC with SKINNY HASH ------------- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full_SKINNY

run_picnic_FULL_SKINNY:
	@echo "\n\n# ------- PICNIC with SKINNY CIPHER + HASH  -------- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full_SKINNY_SKINNY

run_picnic_ASCON_HASH:
	@echo "\n\n# ------------- PICNIC with ASCON HASH ------------- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full_ASCON

run_picnic_FULL_ASCON:
	@echo "\n\n# -------- PICNIC with ASCON CIPHER + HASH --------- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full_ASCON_ASCON

run_picnic_chain:
	@echo "\n\n\n#######################################################\n\n# ---------- PICNIC CHAINED ROUNDS VERSIONS --------- #\n\n#######################################################\n\n# --------- Original PICNIC WITH SHAKE256 --------- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full_chain

run_picnic_SKINNY_HASH_chain:
	@echo "\n\n# ------------ PICNIC with SKINNY HASH ------------- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full_SKINNY_chain

run_picnic_FULL_SKINNY_chain:
	@echo "\n\n# -------- PICNIC with SKINNY CIPHER + HASH --------- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full_SKINNY_SKINNY_chain

run_picnic_ASCON_HASH_chain:
	@echo "\n\n# ------------- PICNIC with ASCON HASH -------------- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full_ASCON_chain

run_picnic_FULL_ASCON_chain:
	@echo "\n\n# -------- PICNIC with ASCON CIPHER + HASH --------- #\n"
	@time $(RUN_EXECUTABLE) -C picnicl1full_ASCON_ASCON_chain



.PHONY: all run_sphincs run_modifyed_sphincs run_picnic run_modifyed_picnic