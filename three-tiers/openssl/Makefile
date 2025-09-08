.ONESHELL:
.DEFAULT_GOAL := help
# Phony targets don't represent actual files.
.PHONY: root-ca intermediate-ca

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


##################################
# CA
##################################
root-ca:  ## Create a new root CA
	@bash ./root-ca.sh


##################################
# Intermediate CA
##################################
intermediate-ca:  ## Create a new intermediate CA (one per account/organization)
	@bash ./intermediate-ca.sh


##################################
# Server Cert
##################################
server-cert:  ## Create a new server certificate (one per service)
	@bash ./server-cert.sh

##################################
# Client Cert
##################################
client-cert:  ## Create a new client certificate (one per service)
	@bash ./client-cert.sh


