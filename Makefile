CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Iinclude
LIB_SRC   = src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/sites.cpp

all: dpi_engine

dpi_engine: src/main.cpp $(LIB_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

test_dpi: tests/test_dpi.cpp $(LIB_SRC)
	$(CXX) $(CXXFLAGS) -fsanitize=address,undefined -o $@ $^

test: test_dpi
	./test_dpi

sample:
	python3 tools/gen_pcap.py samples/test_dpi.pcap

clean:
	rm -f dpi_engine test_dpi
