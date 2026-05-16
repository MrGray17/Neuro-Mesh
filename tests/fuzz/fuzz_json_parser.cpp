// Fuzz target for MitigationEngine JSON parsing (built via make fuzz)
#include <cstdint>
#include <cstddef>
#include <string>
#include "enforcer/MitigationEngine.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    neuro_mesh::MitigationEngine engine(nullptr);

    std::string input(reinterpret_cast<const char*>(data), size);

    // Test schema validation with arbitrary input
    engine.validate_evidence_schema(input);

    return 0;
}
