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

            for (auto& r : final_regs) {
                if (r.first != reg.first && r.second == reg.second) {
                    guessed_instr = "mov " + target_reg_name + "," + sim.reg_name(r.first);
                    instr_found = true;
                    break;
                }
            }

            if (!instr_found && it != init_regs.end()) {
                uint64_t old_val = it->second;
                uint64_t new_val = reg.second;

                if (new_val > old_val) {
                    uint64_t diff = new_val - old_val;
                    if (diff < 0x1000) {
                        guessed_instr = "add " + target_reg_name + ",0x" + to_hex(diff);
                        instr_found = true;
                    }
                }

                if (!instr_found && new_val < old_val) {
                    uint64_t diff = old_val - new_val;
                    if (diff < 0x1000) {
                        guessed_instr = "sub " + target_reg_name + ",0x" + to_hex(diff);
                        instr_found = true;
                    }
                }

                if (!instr_found) {
                    uint64_t diff = old_val ^ new_val;
                    if (diff < 0x1000 || (diff >> 32) == 0) {
                        guessed_instr = "xor " + target_reg_name + ",0x" + to_hex(diff);
                        instr_found = true;
                    }
                }

                if (!instr_found && (new_val & old_val) == new_val) {
                    uint64_t mask = new_val;
                    if (mask < 0x100000000) {
                        guessed_instr = "and " + target_reg_name + ",0x" + to_hex(mask);
                        instr_found = true;
                    }
                }

                if (!instr_found && (new_val | old_val) == new_val) {
                    uint64_t bits_set = new_val & ~old_val;
                    if (bits_set < 0x100000000) {
                        guessed_instr = "or " + target_reg_name + ",0x" + to_hex(bits_set);
                        instr_found = true;
                    }
                }

                if (!instr_found && new_val == old_val + 1) {
                    guessed_instr = "inc " + target_reg_name;
                    instr_found = true;
                }

                if (!instr_found && new_val == old_val - 1) {
                    guessed_instr = "dec " + target_reg_name;
                    instr_found = true;
                }

                if (!instr_found && new_val == (~old_val + 1ULL)) {
                    guessed_instr = "neg " + target_reg_name;
                    instr_found = true;
                }

                if (!instr_found && new_val == ~old_val) {
                    guessed_instr = "not " + target_reg_name;
                    instr_found = true;
                }

                if (!instr_found && old_val != 0 && new_val % old_val == 0) {
                    uint64_t quotient = new_val / old_val;
                    if (quotient && (quotient & (quotient - 1)) == 0) {
                        int shift = 0;
                        while (quotient > 1) { quotient >>= 1; shift++; }
                        guessed_instr = "shl " + target_reg_name + "," + std::to_string(shift);
                        instr_found = true;
                    }
                }

                if (!instr_found && new_val != 0 && old_val % new_val == 0) {
                    uint64_t quotient = old_val / new_val;
                    if (quotient && (quotient & (quotient - 1)) == 0) {
                        int shift = 0;
                        while (quotient > 1) { quotient >>= 1; shift++; }
                        guessed_instr = "shr " + target_reg_name + "," + std::to_string(shift);
                        instr_found = true;
                    }
                }

                if (!instr_found) {
                    for (auto& r : init_regs) {
                        if (r.first == reg.first) continue;
                        if (new_val >= r.second && new_val - r.second < 0x1000) {
                            uint64_t disp = new_val - r.second;
                            guessed_instr = "lea " + target_reg_name + ",[" + sim.reg_name(r.first) + "+" + to_hex(disp) + "]";
                            instr_found = true;
                            break;
                        }
                        else if (new_val < r.second && r.second - new_val < 0x1000) {
                            int64_t disp = (int64_t)new_val - (int64_t)r.second;
                            guessed_instr = "lea " + target_reg_name + ",[" + sim.reg_name(r.first) + to_hex_signed(disp) + "]";
                            instr_found = true;
                            break;
                        }
                    }
                }
            }

            // fallback
            if (!instr_found) {
                guessed_instr = "mov " + target_reg_name + ",0x" + to_hex(reg.second);
            }

            XEDPARSE parse;
            memset(&parse, 0, sizeof(parse));
            parse.x64 = true;
            parse.cip = 0x1000;
            strcpy_s(parse.instr, guessed_instr.c_str());

            if (XEDParseAssemble(&parse) == XEDPARSE_ERROR) {
                std::cerr << "fail in assemble: " << parse.error << std::endl;
            }
            else {
                std::cout << guessed_instr << " -> Machine code: ";
                for (int i = 0; i < parse.dest_size; ++i) {
                    printf("%02X ", parse.dest[i]);
                    result.machine_code.push_back(parse.dest[i]);
                }
                std::cout << std::endl;
            }

            result.instr = guessed_instr;

            std::cout << target_reg_name
                << " = 0x" << std::hex << reg.second
                << std::endl;

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
