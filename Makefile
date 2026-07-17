.PHONY: help tui list env veth veth-clean pcap image test install

IFACE ?= tgt0

help:            ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'

tui:             ## launch the TUI
	python3 -m tgt

list:            ## list protocols and scenarios
	python3 -m tgt list

env:             ## show detected environment
	python3 -m tgt env

veth:            ## create the tgt0 <-> tgt0-mon veth pair (needs sudo)
	sudo python3 -m tgt iface create $(IFACE)

veth-clean:      ## delete the veth pair
	sudo python3 -m tgt iface delete $(IFACE)

pcap:            ## build a sample ot-full pcap (no root)
	python3 -m tgt run -s ot-full --pcap tgt-sample.pcap --count 500
	@echo "wrote tgt-sample.pcap"

test:            ## run the self-test suite
	python3 -m tests.selftest

deps:            ## install system dependencies (needs sudo)
	sudo ./scripts/tgtctl.sh install

service:         ## register + start TGT as a background service (needs sudo)
	sudo ./scripts/tgtctl.sh register
	sudo ./scripts/tgtctl.sh start

service-stop:    ## stop the TGT service
	sudo ./scripts/tgtctl.sh stop

service-status:  ## show TGT service status
	sudo ./scripts/tgtctl.sh status

install:         ## install the tgt command onto PATH
	pip install -e .

image:           ## build the Podman/Docker image
	podman build -t tgt -f Containerfile . || docker build -t tgt -f Containerfile .
