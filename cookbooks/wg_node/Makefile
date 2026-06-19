# Canonical entrypoint for the wg_node cookbook. Humans and CI both run
# `make <target>`. Everything shells out to the Chef Workstation toolchain
# (chef exec rspec, cookstyle, kitchen) so there is no separate Ruby/bundler
# setup to remember.

# Chef Workstation refuses to run without an accepted license; accept it
# non-persistently for every invocation.
export CHEF_LICENSE := accept-no-persist

.DEFAULT_GOAL := help

.PHONY: help install test unit integration lint fmt clean

help: ## Print available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Verify the Chef Workstation toolchain is present
	@command -v chef >/dev/null 2>&1 || { echo "Chef Workstation not found — install from https://www.chef.io/downloads"; exit 1; }
	@chef exec rspec --version
	@cookstyle --version
	@echo "Toolchain OK."

test: ## Run the full RSpec suite (library unit + ChefSpec)
	chef exec rspec

unit: ## Run only the pure-Ruby library unit specs
	chef exec rspec spec/unit

lint: ## Run cookstyle (Chef/Ruby lint) in check mode
	cookstyle .

fmt: ## Auto-correct cookstyle offenses
	cookstyle -a .

integration: ## Run Test Kitchen + InSpec (requires a configured driver; see ROADMAP)
	kitchen test

clean: ## Remove Test Kitchen state and local caches
	rm -rf .kitchen .bundle vendor/bundle
