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

            // Check memory loads
            for (auto& kv : init_regs) {
                std::string src = Simulator::reg_name(kv.first);
                for (auto& ma : result.mem_accesses) {
                    if ((kv.second == ma.address) && (rc.new_value == ma.value) && !ma.is_write) {
                        update_instructions.push_back("mov " + dst + ", [" + src + "]");
                        handled = true;
                        break;
                    }
                }
                if (handled) break;
            }

            if (!handled) {
                // Handle subregister relations
                auto subregs = get_subreg_names(dst);
                bool sub_handled = false;
                for (const std::string& sub_dst : subregs) {
                    for (const auto& rel : result.relations) {
                        if (rel.lhs != sub_dst || !rel.valid) continue;
                        std::string instr;
                        if (rel.rhs.find("init_" + sub_dst + " - ") == 0) {
                            size_t pos = ("init_" + sub_dst + " - ").length();
                            std::string src = rel.rhs.substr(pos);
                            instr = "sub " + sub_dst + ", " + src;
                            update_instructions.push_back(instr);
                            sub_handled = true;
                            break;
                        }
                        else if (rel.rhs.find("init_" + sub_dst + " + ") == 0) {
                            size_t pos = ("init_" + sub_dst + " + ").length();
                            std::string src = rel.rhs.substr(pos);
                            instr = "add " + sub_dst + ", " + src;
                            update_instructions.push_back(instr);
                            sub_handled = true;
                            break;
                        }
                        else if (rel.rhs.find("init_" + sub_dst + " ^ ") == 0) {
                            size_t pos = ("init_" + sub_dst + " ^ ").length();
                            std::string src = rel.rhs.substr(pos);
                            instr = "xor " + sub_dst + ", " + src;
                            update_instructions.push_back(instr);
                            sub_handled = true;
                            break;
                        }
                        else if (rel.rhs == "init_" + sub_dst) {
                            if (rel.delta == 1) {
                                update_instructions.push_back("inc " + sub_dst);
                            }
                            else if (rel.delta == -1) {
                                update_instructions.push_back("dec " + sub_dst);
                            }
                            else if (rel.delta > 0) {
                                update_instructions.push_back("add " + sub_dst + ", " + imm_hex(rel.delta));
                            }
                            else if (rel.delta < 0) {
                                update_instructions.push_back("sub " + sub_dst + ", " + imm_hex(-rel.delta));
                            }
                            sub_handled = true;
                            break;
                        }
                        else if (rel.rhs == "~init_" + sub_dst) {
                            update_instructions.push_back("not " + sub_dst);
                            sub_handled = true;
                            break;
                        }
                        else if (rel.rhs == "-init_" + sub_dst) {
                            update_instructions.push_back("neg " + sub_dst);
                            sub_handled = true;
                            break;
                        }
                        else if (rel.rhs.find("init_" + sub_dst + " << ") == 0) {
                            size_t pos = ("init_" + sub_dst + " << ").length();
                            std::string k = rel.rhs.substr(pos);
                            update_instructions.push_back("shl " + sub_dst + ", " + k);
                            sub_handled = true;
                            break;
                        }
                        else if (rel.rhs.find("init_" + sub_dst + " >> ") == 0) {
                            size_t pos = ("init_" + sub_dst + " >> ").length();
                            std::string k = rel.rhs.substr(pos);
                            update_instructions.push_back("shr " + sub_dst + ", " + k);
                            sub_handled = true;
                            break;
                        }
                        else if (rel.rhs.find("init_" + sub_dst + " sar ") == 0) {
                            size_t pos = ("init_" + sub_dst + " sar ").length();
                            std::string k = rel.rhs.substr(pos);
                            update_instructions.push_back("sar " + sub_dst + ", " + k);
                            sub_handled = true;
                            break;
                        }
                        else if (rel.rhs.find("init_" + sub_dst + " ror ") == 0) {
                            size_t pos = ("init_" + sub_dst + " ror ").length();
                            std::string k = rel.rhs.substr(pos);
                            update_instructions.push_back("ror " + sub_dst + ", " + k);
                            sub_handled = true;
                            break;
                        }
                        else if (rel.delta == 0 && rel.rhs.find("mem[") == 0) {
                            std::string mem = rel.rhs;
                            instr = "mov " + sub_dst + ", " + mem;
                            update_instructions.push_back(instr);
                            sub_handled = true;
                            break;
                        }
                        else if (rel.rhs == "0x0") {
                            instr = "mov " + sub_dst + ", " + imm_hex(rel.delta);
                            update_instructions.push_back(instr);
                            sub_handled = true;
                            break;
                        }
                        else {
                            instr = "mov " + sub_dst + ", " + rel.rhs;
                            update_instructions.push_back(instr);
                            if (rel.delta != 0) {
                                if (rel.delta > 0) {
                                    update_instructions.push_back("add " + sub_dst + ", " + imm_hex(rel.delta));
                                }
                                else if (rel.delta < 0) {
                                    update_instructions.push_back("sub " + sub_dst + ", " + imm_hex(-rel.delta));
                                }
                            }
                            sub_handled = true;
                            break;
                        }
                    }
                    if (sub_handled) break;
                }
                if (sub_handled) {
                    handled = true;
                }
                else {
                    // Full register relations
                    for (auto& rel : result.relations) {
                        if (rel.lhs == dst && rel.valid) {
                            if (rel.rhs.find("init_" + dst + " - ") == 0) {
                                std::string op_part = rel.rhs.substr(("init_" + dst + " - ").length());
                                if (op_part.find("mem[") == 0) {
                                    std::string addr = op_part.substr(4, op_part.size() - 5);
                                    update_instructions.push_back("sub " + dst + ", [" + addr + "]");
                                    handled = true;
                                }
                                else {
                                    update_instructions.push_back("sub " + dst + ", " + op_part);
                                    handled = true;
                                }
                            }
                            else if (rel.rhs.find("init_" + dst + " + ") == 0) {
                                std::string op_part = rel.rhs.substr(("init_" + dst + " + ").length());
                                if (op_part.find("mem[") == 0) {
                                    std::string addr = op_part.substr(4, op_part.size() - 5);
                                    update_instructions.push_back("add " + dst + ", [" + addr + "]");
                                    handled = true;
                                }
                                else {
                                    update_instructions.push_back("add " + dst + ", " + op_part);
                                    handled = true;
                                }
                            }
                            else if (rel.rhs.find("init_" + dst + " ^ ") == 0) {
                                std::string op_part = rel.rhs.substr(("init_" + dst + " ^ ").length());
                                update_instructions.push_back("xor " + dst + ", " + op_part);
                                handled = true;
                            }
                            else if (rel.rhs == "init_" + dst) {
                                if (rel.delta == 1) {
                                    update_instructions.push_back("inc " + dst);
                                }
                                else if (rel.delta == -1) {
                                    update_instructions.push_back("dec " + dst);
                                }
                                else if (rel.delta > 0) {
                                    update_instructions.push_back("add " + dst + ", " + imm_hex(rel.delta));
                                }
                                else if (rel.delta < 0) {
                                    update_instructions.push_back("sub " + dst + ", " + imm_hex(-rel.delta));
                                }
                                handled = true;
                            }
                            else if (rel.rhs == "~init_" + dst) {
                                update_instructions.push_back("not " + dst);
                                handled = true;
                            }
                            else if (rel.rhs == "-init_" + dst) {
                                update_instructions.push_back("neg " + dst);
                                handled = true;
                            }
                            else if (rel.rhs.find("init_" + dst + " << ") == 0) {
                                std::string k = rel.rhs.substr(("init_" + dst + " << ").length());
                                update_instructions.push_back("shl " + dst + ", " + k);
                                handled = true;
                            }
                            else if (rel.rhs.find("init_" + dst + " >> ") == 0) {
                                std::string k = rel.rhs.substr(("init_" + dst + " >> ").length());
                                update_instructions.push_back("shr " + dst + ", " + k);
                                handled = true;
                            }
                            else if (rel.rhs.find("init_" + dst + " sar ") == 0) {
                                std::string k = rel.rhs.substr(("init_" + dst + " sar ").length());
                                update_instructions.push_back("sar " + dst + ", " + k);
                                handled = true;
                            }
                            else if (rel.rhs.find("init_" + dst + " ror ") == 0) {
                                std::string k = rel.rhs.substr(("init_" + dst + " ror ").length());
                                update_instructions.push_back("ror " + dst + ", " + k);
                                handled = true;
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
                                else {
                                    update_instructions.push_back("mov " + dst + ", 0");
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
        }

        // Memory writes
        for (auto& kv : init_regs) {
            std::string base = Simulator::reg_name(kv.first);
            for (auto& ma : result.mem_accesses) {
                if ((kv.second == ma.address) && ma.is_write && ma.source_reg != -1) {
                    std::string src = Simulator::reg_name(ma.source_reg);
                    update_instructions.push_back("mov [" + base + "], " + src);
                }
            }
        }

        // Memory relations
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
    static std::vector<std::string> get_subreg_names(const std::string& full_reg) {
        if (full_reg == "RAX") return { "EAX", "AX", "AL" };
        if (full_reg == "RBX") return { "EBX", "BX", "BL" };
        if (full_reg == "RCX") return { "ECX", "CX", "CL" };
        if (full_reg == "RDX") return { "EDX", "DX", "DL" };
        if (full_reg == "RSI") return { "ESI", "SI", "SIL" };
        if (full_reg == "RDI") return { "EDI", "DI", "DIL" };
        if (full_reg == "RSP") return { "ESP", "SP", "SPL" };
        if (full_reg == "RBP") return { "EBP", "BP", "BPL" };
        if (full_reg == "R8") return { "R8D", "R8W", "R8B" };
        if (full_reg == "R9") return { "R9D", "R9W", "R9B" };
        if (full_reg == "R10") return { "R10D", "R10W", "R10B" };
        if (full_reg == "R11") return { "R11D", "R11W", "R11B" };
        if (full_reg == "R12") return { "R12D", "R12W", "R12B" };
        if (full_reg == "R13") return { "R13D", "R13W", "R13B" };
        if (full_reg == "R14") return { "R14D", "R14W", "R14B" };
        if (full_reg == "R15") return { "R15D", "R15W", "R15B" };
        return {};
    }

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