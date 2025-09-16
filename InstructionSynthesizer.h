#pragma once
#include "simulator.h"
#include "analysis.h"
#include "deps/XEDParse.h"
#include <string>
#include <vector>
#include <iostream>
#include <cstring>
#include <algorithm>  

struct SynthesizedInstr {
    std::string asm_code;
    std::vector<uint8_t> machine_code;
};

class InstructionSynthesizer {
public:
    SynthesizedInstr synthesize(const ExecutionResult& result,
        const RegMap& init_regs,
        const RegMap& final_regs)
    {
        SynthesizedInstr out;
        std::vector<std::string> initial_instructions;
        std::vector<std::string> update_instructions;

        for (auto& rc : result.reg_changes) {
            std::string dst = rc.name;
            bool handled = false;


            for (auto& kv : init_regs) {
                std::string src = Simulator::reg_name(kv.first);
                for (auto& ma : result.mem_accesses) {
                    if ((kv.second == ma.address) && (rc.new_value == ma.value) && !ma.is_write) {
                        initial_instructions.push_back("mov " + dst + ", [" + src + "]");
                        handled = true;
                        break;
                    }
                }
                if (handled) break;
            }

            if (!handled) {
                for (auto& kv : init_regs) {
                    std::string src = Simulator::reg_name(kv.first);
                    if (kv.second == rc.new_value && src != dst) {
                        initial_instructions.push_back("mov " + dst + ", " + src);
                        handled = true;
                    }
                    else if (rc.new_value == rc.old_value + kv.second) {
                        initial_instructions.push_back("add " + dst + ", " + src);
                        handled = true;
                    }
                    else if (rc.new_value == rc.old_value - kv.second) {
                        initial_instructions.push_back("sub " + dst + ", " + src);
                        handled = true;
                    }
                    else if (rc.new_value == (rc.old_value ^ kv.second)) {
                        initial_instructions.push_back("xor " + dst + ", " + src);
                        handled = true;
                    }
                    if (handled) break;
                }
            }

            if (!handled) {
                if (rc.new_value == ~rc.old_value) {
                    initial_instructions.push_back("not " + dst);
                    handled = true;
                }
                else if (rc.new_value == (uint64_t)(-(int64_t)rc.old_value)) {
                    initial_instructions.push_back("neg " + dst);
                    handled = true;
                }
                else if (rc.new_value == rc.old_value + 1) {
                    initial_instructions.push_back("inc " + dst);
                    handled = true;
                }
                else if (rc.new_value == rc.old_value - 1) {
                    initial_instructions.push_back("dec " + dst);
                    handled = true;
                }
            }

            if (!handled) {
                for (int i = 1; i < 64; i++) {
                    if ((int64_t)rc.new_value == ((int64_t)rc.old_value >> i)) {
                        initial_instructions.push_back("sar " + dst + ", " + imm_hex(i));
                        handled = true; break;
                    }
                    if (rc.new_value == (rc.old_value >> i)) {
                        initial_instructions.push_back("shr " + dst + ", " + imm_hex(i));
                        handled = true; break;
                    }
                    if (rc.new_value == (rc.old_value << i)) {
                        initial_instructions.push_back("shl " + dst + ", " + imm_hex(i));
                        handled = true; break;
                    }
                    if (rc.new_value == ror(rc.old_value, i)) {
                        initial_instructions.push_back("ror " + dst + ", " + imm_hex(i));
                        handled = true; break;
                    }
                }
            }

            if (!handled) {
                for (auto& rel : result.relations) {
                    if (rel.lhs == dst && rel.valid) {
                        if (rel.rhs.find("init_" + dst + " - ") == 0) {
                            std::string mem_part = rel.rhs.substr(("init_" + dst + " - ").length());
                            if (mem_part.find("mem[") == 0) {
                                std::string addr = mem_part.substr(4, mem_part.size() - 5);
                                update_instructions.push_back("sub " + dst + ", [" + addr + "]");
                                handled = true;
                            }
                        }
                        else if (rel.rhs.find("init_" + dst + " + ") == 0) {
                            std::string mem_part = rel.rhs.substr(("init_" + dst + " + ").length());
                            if (mem_part.find("mem[") == 0) {
                                std::string addr = mem_part.substr(4, mem_part.size() - 5);
                                update_instructions.push_back("add " + dst + ", [" + addr + "]");
                                handled = true;
                            }
                        }
                        else if (rel.rhs.find("mem[") != std::string::npos) {
                            std::string base = rel.rhs.substr(4, rel.rhs.size() - 5);
                            if (rel.delta != 0) {
                                std::string sign = (rel.delta > 0) ? " + " : " - ";
                                update_instructions.push_back("mov " + dst + ", [" + base + sign + imm_hex(std::abs(rel.delta)) + "]");
                            }
                            else {
                                update_instructions.push_back("mov " + dst + ", [" + base + "]");
                            }
                            handled = true;
                        }
                        else if (rel.rhs == "0x0") {
                            if (rel.delta > 0) {
                                update_instructions.push_back("add " + dst + ", " + imm_hex(rel.delta));
                            }
                            else if (rel.delta < 0) {
                                update_instructions.push_back("sub " + dst + ", " + imm_hex(-rel.delta));
                            }
                            handled = true;
                        }
                        else {
                            if (dst != rel.rhs) {
                                update_instructions.push_back("mov " + dst + ", " + rel.rhs);
                            }
                            if (rel.delta > 0) {
                                update_instructions.push_back("add " + dst + ", " + imm_hex(rel.delta));
                            }
                            else if (rel.delta < 0) {
                                update_instructions.push_back("sub " + dst + ", " + imm_hex(-rel.delta));
                            }
                            handled = true;
                        }
                        if (handled) break;
                    }
                }
            }
        }

        for (auto& kv : init_regs) {
            std::string base = Simulator::reg_name(kv.first);
            for (auto& ma : result.mem_accesses) {
                if ((kv.second == ma.address) && ma.is_write && ma.source_reg != -1) {
                    std::string src = Simulator::reg_name(ma.source_reg);
                    update_instructions.push_back("mov [" + base + "], " + src);
                }
            }
        }


        for (auto& rel : result.relations) {
            if (rel.valid && rel.lhs.find("mem[") == 0) {
                std::string mem_addr = rel.lhs.substr(4, rel.lhs.size() - 5);
                std::string src = rel.rhs;


                if (src.find("mem[") != std::string::npos) {
                    continue; 
                }

                std::string instr;
                if (rel.delta == 0) {

                    instr = "mov [" + mem_addr + "], " + src;
                    update_instructions.push_back(instr);
                }
                else {
                 
                    update_instructions.push_back("mov RAX, " + src);
                    if (rel.delta > 0) {
                        update_instructions.push_back("add RAX, " + imm_hex(rel.delta));
                    }
                    else if (rel.delta < 0) {
                        update_instructions.push_back("sub RAX, " + imm_hex(-rel.delta));
                    }
                    update_instructions.push_back("mov [" + mem_addr + "], RAX");
                }
            }
        }


        std::vector<std::string> instructions = initial_instructions;
        instructions.insert(instructions.end(), update_instructions.begin(), update_instructions.end());

        if (instructions.empty()) {
            instructions.push_back("nop");
        }


        out.asm_code = "";
        for (auto& instr : instructions) {
            out.asm_code += instr + "\n";
        }

        return assemble_and_return(out);
    }

private:
    static std::string imm_hex(int64_t v) {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%llX", std::llabs(v));
        return std::string(buf);
    }

    static std::string to_hex(uint64_t v) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%llX", v);
        return std::string(buf);
    }

    static uint64_t ror(uint64_t val, int n) {
        return (val >> n) | (val << (64 - n));
    }

    SynthesizedInstr assemble_and_return(SynthesizedInstr& instr) {
        SynthesizedInstr final;
        XEDPARSE parse;
        memset(&parse, 0, sizeof(parse));
        parse.x64 = true;
        parse.cip = 0x1000;
        for (auto& line : split_lines(instr.asm_code)) {
            std::string trimmed = line;
            trimmed.erase(0, trimmed.find_first_not_of(" \t"));
            trimmed.erase(trimmed.find_last_not_of(" \t") + 1);
            if (trimmed.empty()) continue;
            strcpy_s(parse.instr, sizeof(parse.instr), trimmed.c_str());
            if (XEDParseAssemble(&parse) == XEDPARSE_ERROR) {
                std::cerr << "Assembly failed for: " << trimmed << " - " << parse.error << "\n";
                final.machine_code.clear();
                continue;
            }
            final.machine_code.insert(final.machine_code.end(), parse.dest, parse.dest + parse.dest_size);
            final.asm_code += trimmed + "\n";
        }
        return final;
    }

    std::vector<std::string> split_lines(const std::string& str) {
        std::vector<std::string> lines;
        std::istringstream iss(str);
        std::string line;
        while (std::getline(iss, line)) {
            if (!line.empty()) lines.push_back(line);
        }
        return lines;
    }
};