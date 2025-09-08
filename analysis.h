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


static std::map<int, std::vector<int64_t>> reg_change_history;
GuessResult guess_instruction(Simulator& sim,
    const RegMap& init_regs,
    const RegMap& final_regs)
{
    GuessResult result;

    // ???? ????? RSP
    uint64_t virtual_rsp = init_regs.at(UC_X86_REG_RSP);

    for (auto& reg : final_regs) {
        if (reg.first == UC_X86_REG_RSP) continue;
        auto it = init_regs.find(reg.first);
        if (it == init_regs.end() || it->second != reg.second) {

            std::string target_reg_name = sim.reg_name(reg.first);
            std::string guessed_instr;
            bool instr_found = false;

            uint64_t old_val = it != init_regs.end() ? it->second : 0;
            uint64_t new_val = reg.second;

            // ---------- PUSH/POP using memory accesses ----------
            for (auto& m : sim.mem_accesses) {
                if (instr_found) break;

                // POP pattern: READ from [virtual RSP] ? reg
                if (!m.is_write && m.value == new_val && m.addr == virtual_rsp) {
                    guessed_instr = "pop " + target_reg_name;
                    instr_found = true;
                    virtual_rsp += 8;
                    break;
                }

                // PUSH pattern: WRITE reg ? [virtual RSP - 8]
                if (m.is_write && m.value == old_val && m.addr == virtual_rsp - 8) {
                    guessed_instr = "push " + target_reg_name;
                    instr_found = true;
                    virtual_rsp -= 8;
                    break;
                }

                // MOV from memory
                if (!instr_found && !m.is_write && m.value == new_val) {
                    guessed_instr = "mov " + target_reg_name + ", [0x" + to_hex(m.addr) + "]";
                    instr_found = true;
                    break;
                }
            }

            // ---------- MOV from another reg ----------
            if (!instr_found) {
                for (auto& r : final_regs) {
                    if (r.first != reg.first && r.second == reg.second) {
                        guessed_instr = "mov " + target_reg_name + "," + sim.reg_name(r.first);
                        instr_found = true;
                        break;
                    }
                }
            }

            // ---------- XOR pattern ----------
            if (!instr_found) {
                for (auto& r : init_regs) {
                    if (r.first == reg.first) continue;
                    if (final_regs.at(r.first) == r.second) { // unchanged reg
                        if ((old_val ^ r.second) == new_val) {
                            guessed_instr = "xor " + target_reg_name + "," + sim.reg_name(r.first);
                            instr_found = true;
                            break;
                        }
                    }
                }
            }

            // ---------- ADD/SUB pattern ----------
            if (!instr_found) {
                int64_t diff = static_cast<int64_t>(new_val) - static_cast<int64_t>(old_val);
                if (diff > 0 && diff < 0x1000) { guessed_instr = "add " + target_reg_name + ",0x" + to_hex(diff); instr_found = true; }
                if (!instr_found && diff < 0 && -diff < 0x1000) { guessed_instr = "sub " + target_reg_name + ",0x" + to_hex(-diff); instr_found = true; }
            }

            // ---------- SHIFT patterns (shl/shr) ----------
            if (!instr_found && old_val != 0) {
                uint64_t quotient = 0;
                if (new_val > old_val && new_val % old_val == 0) quotient = new_val / old_val;
                if (new_val < old_val && old_val % new_val == 0) quotient = old_val / new_val;
                if (quotient && (quotient & (quotient - 1)) == 0) { // power of 2
                    int shift = 0;
                    while (quotient > 1) { quotient >>= 1; shift++; }
                    guessed_instr = (new_val > old_val ? "shl " : "shr ") + target_reg_name + "," + std::to_string(shift);
                    instr_found = true;
                }
            }

            // ---------- Fallback ----------
            if (!instr_found) guessed_instr = "mov " + target_reg_name + ",0x" + to_hex(new_val);

            // ---------- Assemble ----------
            XEDPARSE parse;
            memset(&parse, 0, sizeof(parse));
            parse.x64 = true;
            parse.cip = 0x1000;
            strcpy_s(parse.instr, guessed_instr.c_str());

            if (XEDParseAssemble(&parse) == XEDPARSE_ERROR) {
                std::cerr << "fail in assemble: " << parse.error << ", fallback..." << std::endl;
                guessed_instr = "mov " + target_reg_name + ",0x" + to_hex(new_val);
                memset(&parse, 0, sizeof(parse));
                parse.x64 = true;
                parse.cip = 0x1000;
                strcpy_s(parse.instr, guessed_instr.c_str());
                XEDParseAssemble(&parse);
            }

            // ---------- Combine multiple instructions ----------
            if (!result.instr.empty()) result.instr += "; ";
            result.instr += guessed_instr;

            for (int i = 0; i < parse.dest_size; ++i) result.machine_code.push_back(parse.dest[i]);
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
