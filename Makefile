base_path := $(shell pwd)

default:
	$(error Please specify a make target (see README.md)Usage:make deps-env OR make build)

deps-env:
	rm -rf ${base_path}/ngsdn-tutorial
	git clone -b master https://github.com/opennetworkinglab/ngsdn-tutorial
	cd ${base_path}/ngsdn-tutorial && make pull-deps

build: clean
	@mkdir build
	mv src/datapath/upf.p4 ngsdn-tutorial/main.p4
	cd ${base_path}/ngsdn-tutorial && make p4-build
	cp ngsdn-tutorial/p4src/build/bmv2.json build/
	cp ngsdn-tutorial/p4src/build/p4info.txt build/
	go build src/control/main.go -o build/cp-upf
	cp test_script/send_gtp_uplink.py ./ngsdn-tutorial/mininet/
	cp test_script/send_udp_downlink.py ./ngsdn-tutorial/mininet/
clean:
	@rm -rf build
	@rm -f ./ngsdn-tutorial/mininet/send_gtp_uplink.py
	@rm -f ./ngsdn-tutorial/mininet/send_udp_downlink.py


