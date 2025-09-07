#include <iostream>
#include <cstring>
#include "simulator.h"
#include "deps/XEDParse.h"

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

    std::cout << "--- Registers changed ---\n";

    for (auto& reg : final_regs) {
        auto it = init_regs.find(reg.first);
        if (it == init_regs.end() || it->second != reg.second) {
           
            std::string target_reg_name = sim.reg_name(reg.first);
            std::string src_reg_name;
            for (auto& r : final_regs) {
                if (r.first != reg.first && r.second == reg.second) {
                    src_reg_name = sim.reg_name(r.first);
                    break;
                }
            }

            if (!src_reg_name.empty()) {

                std::string instr = "mov " + target_reg_name + "," + src_reg_name;
                XEDPARSE parse;
                memset(&parse, 0, sizeof(parse));
                parse.x64 = true;
                parse.cip = 0x1000;
                strcpy_s(parse.instr, instr.c_str());

                if (XEDParseAssemble(&parse) == XEDPARSE_ERROR) {
                    std::cerr << "fail in assembel: " << parse.error << std::endl;
                    continue;
                }

                std::cout << instr << " -> Machine code: ";
                for (int i = 0; i < parse.dest_size; ++i)
                    printf("%02X ", parse.dest[i]);
                std::cout << std::endl;
            }

            std::cout << target_reg_name
                << " = 0x" << std::hex << reg.second
                << std::endl;
        }
    }

    std::cout << "\n--- Memory accesses ---\n";
    for (auto& m : sim.mem_accesses) {
        std::cout << (m.is_write ? "[WRITE] " : "[READ] ")
            << "0x" << std::hex << m.addr
            << " val=0x" << m.value
            << (m.reg_src != -1 ? " reg value : " + Simulator::reg_name(m.reg_src) : "")
            << "\n";
    }

    return 0;
}
