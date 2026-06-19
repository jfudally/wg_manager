# Shared RSpec/ChefSpec setup for the wg_node cookbook.
#
# Unit specs (spec/unit) exercise the pure-Ruby WgManager::ApiClient
# library directly. Recipe specs (spec/recipes) drive the recipes through
# ChefSpec's in-memory Chef run. Both share this helper.

require 'chefspec'

# The API client is a plain-Ruby library (no Chef DSL), so we load it
# directly rather than through Chef's library autoloader. This keeps the
# unit specs fast and free of a full Chef run.
require_relative '../libraries/wg_manager_api'

RSpec.configure do |config|
  config.color = true
  config.formatter = :documentation
  # Keep ChefSpec/Chef log noise out of the test output; failures still
  # surface through RSpec.
  config.log_level = :error

  # Default platform/version for ChefSpec runners so individual specs
  # don't have to repeat it. Ubuntu 22.04 matches the Phase 1 target.
  config.platform = 'ubuntu'
  config.version = '22.04'
end
