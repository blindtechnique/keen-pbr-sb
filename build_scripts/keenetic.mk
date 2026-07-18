## Keenetic packaging ###########################################################
#
# Variables (all overridable via environment or CLI):
#   KEENETIC_CONFIG        — Entware config name, e.g. mipsel-3.4
#   KEENETIC_VERSION       — Keenetic channel version for build/packages layout
#   KEENETIC_DOCKER_IMAGE  — Docker image to use for building (default: derived from config)

KEENETIC_CONFIG       ?=
KEENETIC_VERSION      ?=
KEENETIC_DOCKER_IMAGE ?= ghcr.io/maksimkurb/entware-builder:$(KEENETIC_CONFIG)
KEENETIC_BUILD_JOBS   ?= 2
KEENETIC_TRANSPORT_ARCH = $(if $(findstring aarch64,$(KEENETIC_CONFIG)),aarch64,$(if $(findstring mipsel,$(KEENETIC_CONFIG)),mipsel,$(if $(findstring mips-,$(KEENETIC_CONFIG)),mips,$(if $(findstring armv7,$(KEENETIC_CONFIG)),armv7,$(if $(findstring x64,$(KEENETIC_CONFIG)),x64,)))))

define _require_nonempty
$(if $(strip $($1)),,$(error $1 is required for target '$2'))
endef

.PHONY: keenetic-packages

keenetic-packages: transport-manager-build ## Build Keenetic packages inside Entware Docker container
	$(call _require_nonempty,KEENETIC_CONFIG,$@)
	$(call _require_nonempty,KEENETIC_VERSION,$@)
	@test -n "$(KEENETIC_TRANSPORT_ARCH)" || { echo "Unsupported transport-manager architecture for $(KEENETIC_CONFIG)"; exit 1; }
	@echo "[keenetic-packages] config: KEENETIC_CONFIG=$(KEENETIC_CONFIG) KEENETIC_VERSION=$(KEENETIC_VERSION) KEENETIC_DOCKER_IMAGE=$(KEENETIC_DOCKER_IMAGE)"
	mkdir -p build/packages
	docker run --rm --user root \
	  --entrypoint /bin/bash \
	  -e KEEN_PBR_RELEASE_OVERRIDE="$(KEEN_PBR_RELEASE)" \
	  -e KEEN_PBR_JOBS="$(KEENETIC_BUILD_JOBS)" \
	  -e KEEN_PBR_TRANSPORT_MANAGER_BIN="/workspace/build/dist/transport-manager/transport-manager-$(KEENETIC_TRANSPORT_ARCH)" \
	  -v "$(abspath .):/workspace" \
	  "$(KEENETIC_DOCKER_IMAGE)" \
	  -lc 'set -e; \
	    sh /workspace/build_scripts/build-keenetic-package.sh /workspace /home/me/Entware; \
	    mkdir -p /workspace/build/packages; \
	    sh /workspace/build_scripts/collect-keenetic.sh \
	      /workspace /home/me/Entware/bin /workspace/build/packages \
	      "$(KEENETIC_CONFIG)" "$(KEENETIC_VERSION)"'
