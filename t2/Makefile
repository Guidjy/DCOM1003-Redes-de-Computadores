BMV2_SWITCH_EXE = simple_switch_grpc
TOPO = pod-topo/topology.json

include ../../utils/Makefile

# Garante a criação dos arquivos com os nomes e extensões exatos que o run_exercise.py espera
$(BUILD_DIR)/nat.p4.p4info.txt: $(BUILD_DIR)/nat.p4.p4info.txtpb
	cp $< $@

$(BUILD_DIR)/nat.p4.json: $(BUILD_DIR)/nat.json
	cp $< $@

# Associa as cópias ao fluxo de compilação
build: $(BUILD_DIR)/nat.p4.p4info.txt $(BUILD_DIR)/nat.p4.json
