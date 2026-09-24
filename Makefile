# Airlock (C++) -- common tasks.
BUILD ?= build
CAPTURE ?= captures/synthetic.pcap
JOBS ?= 8

.PHONY: help build test handshake attacks synth analyze report demo sanitize clean

help:
	@echo "build      configure and compile (Release) into \$$BUILD"
	@echo "test       run the full test suite"
	@echo "handshake  run one authenticated Diffie-Hellman handshake"
	@echo "attacks    run every adversary simulation"
	@echo "synth      regenerate the synthetic capture"
	@echo "analyze    analyze \$$CAPTURE (default: $(CAPTURE))"
	@echo "report     write docs/sample-report.txt and a JSON report"
	@echo "demo       handshake, attacks, and capture analysis end to end"
	@echo "sanitize   build and test under AddressSanitizer and UBSan"

$(BUILD)/CMakeCache.txt:
	cmake -S . -B $(BUILD) -DCMAKE_BUILD_TYPE=Release

build: $(BUILD)/CMakeCache.txt
	cmake --build $(BUILD) -j $(JOBS)

test: build
	ctest --test-dir $(BUILD) --output-on-failure -j $(JOBS)

handshake: build
	$(BUILD)/akex handshake

attacks: build
	$(BUILD)/akex attacks

synth: build
	$(BUILD)/wifi synth $(CAPTURE)

analyze: build
	$(BUILD)/wifi analyze $(CAPTURE)

report: synth
	$(BUILD)/wifi analyze $(CAPTURE) --json captures/reports/synthetic.json \
		> docs/sample-report.txt
	@echo "wrote docs/sample-report.txt and captures/reports/synthetic.json"

demo: handshake attacks analyze

# Homebrew's GoogleTest is not built with ASan container annotations, which
# produces false container-overflow reports inside gtest itself.
sanitize:
	cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
		-DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"
	ASAN_OPTIONS=detect_container_overflow=0 cmake --build build-asan -j $(JOBS)
	ASAN_OPTIONS=detect_container_overflow=0 ctest --test-dir build-asan --output-on-failure -j $(JOBS)

clean:
	rm -rf $(BUILD) build-asan
	rm -f captures/reports/*.json
