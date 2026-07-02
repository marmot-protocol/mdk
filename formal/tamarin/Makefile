TAMARIN ?= tamarin-prover
MODEL := distributed_convergence_v0.spthy

.PHONY: prove interactive

prove:
	@tmp=$$(mktemp); \
	$(TAMARIN) $(MODEL) --prove > "$$tmp" 2>&1; \
	status=$$?; \
	if [ $$status -ne 0 ]; then \
		cat "$$tmp"; \
		rm -f "$$tmp"; \
		exit $$status; \
	fi; \
	if ! grep -q '^summary of summaries:' "$$tmp"; then \
		echo "error: Tamarin completed but no summary block was found"; \
		cat "$$tmp"; \
		rm -f "$$tmp"; \
		exit 1; \
	fi; \
	awk 'seen || /^summary of summaries:/ { seen=1; print }' "$$tmp"; \
	rm -f "$$tmp"

interactive:
	$(TAMARIN) interactive $(MODEL) --quit-on-warning
