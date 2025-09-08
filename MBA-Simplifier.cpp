#include <iostream>
#include <cstring>
#include "simulator.h"
#include "deps/XEDParse.h"
#include "analysis.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <hex>\n";
        return 1;
    }

    std::string hex;
    for (int i = 1; i < argc; i++) hex += argv[i];

    auto code = Simulator::hex_to_bytes(hex);
    if (code.empty()) {
        std::cerr << "No code\n";
        return 1;
    }

    Simulator sim;
    RegMap init_regs = Simulator::make_random_regs();
    RegMap final_regs;
    sim.emulate(code, init_regs, final_regs);



    auto guess = guess_instruction(sim, init_regs, final_regs);


    if (!guess.machine_code.empty()) {
        auto result = InstructionTester::test_equivalence(code, guess.machine_code, TestMode::RANDOM_REGS);

        if (result.match) {
            std::cout << "[OK] " << guess.instr << " behaves same as original.\n";
        }
        else {
            std::cout << "[FAIL] Predicted instr mismatch!\n";
        }
    }

    print_memory_accesses(sim);

    return 0;
}
