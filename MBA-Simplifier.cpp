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

    const int NUM_TRIALS = 10;
    std::map<std::string, int> instr_votes; 

    for (int trial = 0; trial < NUM_TRIALS; trial++) {
        RegMap init_regs = Simulator::make_random_regs();
        RegMap final_regs;
        sim.emulate(code, init_regs, final_regs);

        auto guess = guess_instruction(sim, init_regs, final_regs);

        if (!guess.instr.empty()) {
            instr_votes[guess.instr]++;
        }
    }


    std::string best_instr;
    int max_votes = 0;
    for (auto& kv : instr_votes) {
        if (kv.second > max_votes) {
            max_votes = kv.second;
            best_instr = kv.first;
        }
    }

    std::cout << "[Best guess after " << NUM_TRIALS << " trials]: " << best_instr << "\n";


    RegMap init_regs = Simulator::make_random_regs();
    RegMap final_regs;
    sim.emulate(code, init_regs, final_regs);

    auto final_guess = guess_instruction(sim, init_regs, final_regs);

    if (!final_guess.machine_code.empty()) {
        auto result = InstructionTester::test_equivalence(code, final_guess.machine_code, TestMode::RANDOM_REGS);

        if (result.match) {
            std::cout << "\033[1;32m[OK] " << final_guess.instr << " behaves same as original.\033[0m\n";

            std::cout << "Machine code: ";
            for (auto b : final_guess.machine_code) {
                printf("%02X ", b);
            }
            std::cout << std::endl;
        }
        else {
            std::cout << "\033[1;31m[FAIL] Predicted instr mismatch!\033[0m\n";

            std::cout << "Predicted machine code: ";
            for (auto b : final_guess.machine_code) {
                printf("%02X ", b);
            }
            std::cout << std::endl;
        }
    }


    print_memory_accesses(sim);

    return 0;
}
