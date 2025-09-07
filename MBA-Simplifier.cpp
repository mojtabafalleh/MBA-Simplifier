#include <iostream>
#include "simulator.h"

int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "Usage: " << argv[0] << " <hex>\n"; return 1; }

    std::string hex;
    for (int i = 1; i < argc; i++) hex += argv[i];

    auto code = Simulator::hex_to_bytes(hex);
    if (code.empty()) { std::cerr << "No code\n"; return 1; }

    Simulator sim;
    RegMap init_regs = Simulator::make_random_regs();
    RegMap final_regs;

    sim.emulate(code, init_regs, final_regs);

    std::cout << "--- registr simplify ---\n";
    for (auto& r : final_regs) {
        for (auto& i : init_regs) {

            if ((r.first == i.first) && (r.second == i.second))
                break;

            if ((i.second == r.second) && !(i.first == r.first))
                std::cout << Simulator::reg_name(r.first) << " = " << Simulator::reg_name(i.first) << "\n";

            if ( (i.first == r.first) && !(i.second == r.second))
                std::cout << Simulator::reg_name(r.first) << " = " <<std::hex << r.second << "\n";


        }
    }

    std::cout << "\n--- Memory accesses ---\n";
    for (auto& m : sim.mem_accesses) {
        std::cout << (m.is_write ? "[WRITE] " : "[READ] ")
            << "0x" << std::hex << m.addr
            << " val=0x" << m.value
            << (m.reg_src != -1 ? " reg value : " + Simulator::reg_name(m.reg_src) : "") << "\n";
    }
}
