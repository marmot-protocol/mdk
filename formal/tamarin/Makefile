TAMARIN ?= tamarin-prover
DERIVCHECK_TIMEOUT ?= 60
MODEL := distributed_convergence_v0.spthy

.PHONY: prove interactive

prove:
	@python3 -B prove_tamarin.py -- $(TAMARIN) $(MODEL) --prove --quit-on-warning \
		--derivcheck-timeout=$(DERIVCHECK_TIMEOUT)

interactive:
	$(TAMARIN) interactive $(MODEL) --quit-on-warning
