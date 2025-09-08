.PHONY: help root-ca intermediate-ca server-cert client-cert

help:
	@echo "Available commands:"
	@echo "  root-ca          - Create a new Root CA"
	@echo "  intermediate-ca  - Create a new Intermediate CA"
	@echo "  server-cert      - Create a new server certificate"
	@echo "  client-cert      - Create a new client certificate"

root-ca:
	@bash ../step/root-ca.sh

intermediate-ca:
	@bash ../step/intermediate-ca.sh

server-cert:
	@bash ../step/server-cert.sh

client-cert:
	@bash ../step/client-cert.sh
