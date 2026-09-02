#include "ndms_http_config_resource.hpp"

// The shared state machine lives in ndms_rci_json_resource.cpp. This explicit
// translation unit keeps the structured HTTP-config specialization visible in
// production and focused build manifests.
