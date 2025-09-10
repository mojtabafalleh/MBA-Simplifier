#include <iostream>
#include <windows.h> 
#include <cstring>
#include "simulator.h"
#include "analysis.h"
#include "InstructionSynthesizer.h"

void print_colored(const std::string& text, WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
    std::cout << text << std::endl;
    SetConsoleTextAttribute(hConsole, 7); 
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <hex>\n";
        return 1;
    }

    std::string hex;
    for (int i = 1; i < argc; i++) hex += argv[i];

    auto original_code = Simulator::hex_to_bytes(hex);
    if (original_code.empty()) {
        std::cerr << "No code\n";
        return 1;
    }

    Simulator sim;
    RegMap init_regs = Simulator::make_random_regs();
    RegMap final_regs_original;
    sim.emulate(original_code, init_regs, final_regs_original);

    ExecutionResult result = analyze_execution(sim, init_regs, final_regs_original);

    InstructionSynthesizer synth;
    auto out = synth.synthesize(result, init_regs, final_regs_original);

    std::cout << "Assembly: " << out.asm_code << "\n";
    std::cout << "Machine code: ";
    for (auto b : out.machine_code) {
        printf("%02X ", b);
    }
    std::cout << std::endl;

    print_register_changes(result);
    print_memory_accesses(result);

    RegMap final_regs_synth;
    init_regs = Simulator::make_random_regs();
    sim.emulate(original_code, init_regs, final_regs_original);
    sim.emulate(out.machine_code, init_regs, final_regs_synth);

    bool success = true;
    for (auto& reg : final_regs_original) {
        if (final_regs_synth[reg.first] != reg.second) {
            success = false;
            std::cout << "Mismatch in register " << sim.reg_name(reg.first)
                << ": original=" << reg.second
                << ", synthesized=" << final_regs_synth[reg.first] << "\n";
        }
    }

    if (success) {
        print_colored("succsess.", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    }
    else {
        print_colored("fail.", FOREGROUND_RED | FOREGROUND_INTENSITY);
    }

    return 0;
}
