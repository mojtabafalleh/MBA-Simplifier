#pragma once
#include "simulator.h"
#include "analysis.h"
#include "deps/XEDParse.h"
#include <string>
#include <vector>
#include <iostream>
#include <cstring>

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
        std::vector<std::string> instructions;



        for (auto& rc : result.reg_changes) {
                std::string dst = rc.name;
                bool handled = false;
                for (auto& kv : init_regs) {
                    std::string src = Simulator::reg_name(kv.first);
                       
                    for (auto& ma : result.mem_accesses) {

                        if ((kv.second == ma.addr) && (rc.new_val == ma.value) && !ma.is_write) {
                            instructions.push_back("mov " + rc.name + ", [" + Simulator::reg_name(kv.first) + "]");
                            handled = true;
                            break;
                        }
                    }

                    if (!handled && kv.second == rc.new_val && src != dst) {
                        instructions.push_back("mov " + dst + ", " + src);
                        handled = true;
                        break;
                    }

                    if (!handled && rc.new_val == rc.old_val + kv.second) {
                        instructions.push_back("add " + dst + ", " + src);
                        handled = true;
                        break;
                    }

                    if (!handled && rc.new_val == rc.old_val - kv.second) {
                        instructions.push_back("sub " + dst + ", " + src);
                        handled = true;
                        break;
                    }

                    if (!handled && rc.new_val == (rc.old_val ^ kv.second)) {
                        instructions.push_back("xor " + dst + ", " + src);
                        handled = true;
                        break;
                    }
                }

                if (!handled) {
                    if (rc.new_val == ~rc.old_val) {
                        instructions.push_back("not " + dst);
                        handled = true;
                    }
                    else if (rc.new_val == (uint64_t)(-(int64_t)rc.old_val)) {
                        instructions.push_back("neg " + dst);
                        handled = true;
                    }
                    else if (rc.new_val == rc.old_val + 1) {
                        instructions.push_back("inc " + dst);
                        handled = true;
                    }
                    else if (rc.new_val == rc.old_val - 1) {
                        instructions.push_back("dec " + dst);
                        handled = true;
                    }
                }

                if (!handled) {
                    for (int i = 1; i < 64; i++) {
                        if ((int64_t)rc.new_val == ((int64_t)rc.old_val >> i)) {
                            instructions.push_back("sar " + dst + ", " + imm_hex(i));
                            handled = true; break;
                        }
                        if (rc.new_val == (rc.old_val >> i)) {
                            instructions.push_back("shr " + dst + ", " + imm_hex(i));
                            handled = true; break;
                        }
                        if (rc.new_val == (rc.old_val << i)) {
                            instructions.push_back("shl " + dst + ", " + imm_hex(i));
                            handled = true; break;
                        }
                        if (rc.new_val == ror(rc.old_val, i)) {
                            instructions.push_back("ror " + dst + ", " + imm_hex(i));
                            handled = true; break;
                        }
                    }
                }

                if (!handled) {
                    instructions.push_back("mov " + dst + ", 0x" + to_hex(rc.new_val));
                }
            }
        for (auto& kv : init_regs) {

                for (auto& ma : result.mem_accesses) {
                    std::cout << (kv.second == ma.addr) && ma.is_write;
                    if ((kv.second == ma.addr) && ma.is_write) {
                        instructions.push_back("mov [" + Simulator::reg_name(kv.first) + "], " + Simulator::reg_name(ma.reg_src));
                    }

                }

        }



        
         if (instructions.empty())
              instructions.push_back("nop");

        out.asm_code = "";
        for (auto& instr : instructions) {
            out.asm_code += instr + "\n";
        }

        return assemble_and_return(out);
    }


private:
    static std::string imm_hex(int v) {
        char buf[32];
        sprintf(buf, "0x%X", v);
        return std::string(buf);
    }

    static std::string to_hex(uint64_t v) {
        char buf[32];
        sprintf(buf, "%llX", v);
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
            strcpy_s(parse.instr, line.c_str());
            if (XEDParseAssemble(&parse) == XEDPARSE_ERROR) {
                std::cerr << "Assembly failed: " << parse.error << "\n";
                final.machine_code.clear();
                continue;
            }
            final.machine_code.insert(final.machine_code.end(), parse.dest, parse.dest + parse.dest_size);
            final.asm_code += line + "\n";
        }

        return final;
    }

    std::vector<std::string> split_lines(const std::string& str) {
        std::vector<std::string> lines;
        size_t pos = 0, prev = 0;
        while ((pos = str.find('\n', prev)) != std::string::npos) {
            std::string line = str.substr(prev, pos - prev);
            if (!line.empty()) lines.push_back(line);
            prev = pos + 1;
        }
        if (prev < str.size()) lines.push_back(str.substr(prev));
        return lines;
    }

};
