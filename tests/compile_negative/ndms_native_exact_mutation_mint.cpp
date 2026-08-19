#include "../../src/keenetic/ndms_native_exact_mutation_transport.hpp"

namespace keen_pbr3 {

// Regression probe: defining the previously-friended coordinator name in an
// unrelated production TU must not grant access to the private mint key.
class NdmsNativePanelDeleteCoordinator final {
public:
    static NdmsNativeExactMutationDispatchCapability mint() {
        return NdmsNativeExactMutationDispatchCapability{
            NdmsNativeExactMutationDispatchCapability::ConstructionKey{}};
    }
};

} // namespace keen_pbr3
