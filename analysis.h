#include "simulator.h"
#include "deps/XEDParse.h"

#include <iostream>
#include <cstring>
// ---------------- Utils ----------------
std::string to_hex(uint64_t val) {
    std::ostringstream oss;
    oss << std::hex << val;
    return oss.str();
}

std::string to_hex_signed(int64_t val) {
    std::ostringstream oss;
    if (val >= 0) oss << "+" << std::hex << val;
    else oss << "-" << std::hex << (-val);
    return oss.str();
}

// ---------------- Analyzer ----------------
struct GuessResult {
    std::string instr;
    std::vector<uint8_t> machine_code;
};

// History map: reg -> list of diffs
static std::map<int, std::vector<int64_t>> reg_change_history;

GuessResult guess_instruction(Simulator& sim,
    const RegMap& init_regs,
    const RegMap& final_regs)
{
    GuessResult result;

    for (auto& reg : final_regs) {
        auto it = init_regs.find(reg.first);
        if (it == init_regs.end() || it->second != reg.second) {

            std::string target_reg_name = sim.reg_name(reg.first);
            std::string guessed_instr;
            bool instr_found = false;

            uint64_t old_val = it != init_regs.end() ? it->second : 0;
            uint64_t new_val = reg.second;
            int64_t diff = static_cast<int64_t>(new_val) - static_cast<int64_t>(old_val);


            reg_change_history[reg.first].push_back(diff);

            // Pattern recognition: pop/push heuristics
            if (reg.first != UC_X86_REG_RSP) {
                auto& rsp_history = reg_change_history[UC_X86_REG_RSP];
                if (!rsp_history.empty() && rsp_history.back() == 8 && diff == 0) {
   
                    guessed_instr = "pop " + target_reg_name;
                    instr_found = true;
                }
            }

       
            for (auto& r : final_regs) {
                if (r.first != reg.first && r.second == reg.second) {
                    guessed_instr = "mov " + target_reg_name + "," + sim.reg_name(r.first);
                    instr_found = true;
                    break;
                }
            }


            if (!instr_found && it != init_regs.end()) {
                if (diff > 0 && diff < 0x1000) { guessed_instr = "add " + target_reg_name + ",0x" + to_hex(diff); instr_found = true; }
                if (!instr_found && diff < 0 && -diff < 0x1000) { guessed_instr = "sub " + target_reg_name + ",0x" + to_hex(-diff); instr_found = true; }
            }

            // fallback
            if (!instr_found) guessed_instr = "mov " + target_reg_name + ",0x" + to_hex(new_val);

            // Assemble
            XEDPARSE parse;
            memset(&parse, 0, sizeof(parse));
            parse.x64 = true;
            parse.cip = 0x1000;
            strcpy_s(parse.instr, guessed_instr.c_str());

            if (XEDParseAssemble(&parse) == XEDPARSE_ERROR) {
                std::cerr << "fail in assemble: " << parse.error << std::endl;
            }
            else {
                for (int i = 0; i < parse.dest_size; ++i) result.machine_code.push_back(parse.dest[i]);
            }

            result.instr = guessed_instr;
            break; 
        }
    }

    return result;
}



void print_register_changes(Simulator& sim,
    const RegMap& init_regs,
    const RegMap& final_regs) {
    std::cout << "--- Registers changed ---\n";
    for (auto& reg : final_regs) {
        auto it = init_regs.find(reg.first);
        if (it == init_regs.end() || it->second != reg.second) {
            std::cout << reg.first<<"  " << reg.second;
        }
    }
}

void print_memory_accesses(Simulator& sim) {
    std::cout << "\n--- Memory accesses ---\n";
    for (auto& m : sim.mem_accesses) {
        std::cout << (m.is_write ? "[WRITE] " : "[READ] ")
            << "0x" << std::hex << m.addr
            << " val=0x" << m.value
            << (m.reg_src != -1 ? " reg value : " + Simulator::reg_name(m.reg_src) : "")
            << "\n";
    }
}
