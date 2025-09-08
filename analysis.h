#include "simulator.h"
#include "deps/XEDParse.h"
#include <iostream>
#include <cstring>
#include <vector>
#include <sstream>
#include <cmath>

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

void assemble_instruction(const std::string& instr, std::vector<uint8_t>& machine_code) {
    XEDPARSE parse;
    memset(&parse, 0, sizeof(parse));
    parse.x64 = true;
    parse.cip = 0x1000;
    strcpy_s(parse.instr, instr.c_str());

    if (XEDParseAssemble(&parse) == XEDPARSE_ERROR) {
        std::cerr << "Assembly failed: " << parse.error << "\n";
        return;
    }

    machine_code.insert(machine_code.end(), parse.dest, parse.dest + parse.dest_size);
}

// ---------------- RSP Handling ----------------
bool handle_rsp_change(Simulator& sim, uint64_t& virtual_rsp,
    uint64_t old_rsp, uint64_t new_rsp,
    std::string& instr, std::vector<uint8_t>& machine_code)
{
    int64_t diff = static_cast<int64_t>(new_rsp) - static_cast<int64_t>(old_rsp);
    std::string guessed_instr;

    if (diff > 0 && diff < 0x1000)
        guessed_instr = "add rsp, 0x" + to_hex(diff);
    else if (diff < 0 && -diff < 0x1000)
        guessed_instr = "sub rsp, 0x" + to_hex(-diff);
    else if (diff >= -0x8000 && diff <= 0x7FFF)
        guessed_instr = "lea rsp, [rsp" + to_hex_signed(diff) + "]";

    if (!guessed_instr.empty()) {
        assemble_instruction(guessed_instr, machine_code);
        instr = guessed_instr;
        virtual_rsp = new_rsp;
        return true;
    }

    return false;
}

// ---------------- Single Register Guess ----------------
std::string guess_register_instruction(Simulator& sim,
    uint64_t old_val, uint64_t new_val,
    const std::string& reg_name,
    const RegMap& init_regs,
    const RegMap& final_regs,
    uint64_t virtual_rsp)
{
    // XOR reg, reg
    if (new_val == 0) return "xor " + reg_name + "," + reg_name;

    // INC/DEC/ADD/SUB
    int64_t diff = static_cast<int64_t>(new_val) - static_cast<int64_t>(old_val);
    if (diff == 1) return "inc " + reg_name;
    if (diff == -1) return "dec " + reg_name;
    if (diff > 0 && diff < 0x1000) return "add " + reg_name + ",0x" + to_hex(diff);
    if (diff < 0 && -diff < 0x1000) return "sub " + reg_name + ",0x" + to_hex(-diff);

    // Fallback MOV
    return "mov " + reg_name + ",0x" + to_hex(new_val);
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
    uint64_t virtual_rsp = init_regs.at(UC_X86_REG_RSP);

    // Check RSP first
    auto rsp_final_it = final_regs.find(UC_X86_REG_RSP);
    if (rsp_final_it != final_regs.end() && rsp_final_it->second != virtual_rsp) {
        handle_rsp_change(sim, virtual_rsp, virtual_rsp, rsp_final_it->second,
            result.instr, result.machine_code);
    }

    // Check other registers
    for (auto& reg : final_regs) {
        if (reg.first == UC_X86_REG_RSP) continue;
        auto it = init_regs.find(reg.first);
        uint64_t old_val = it != init_regs.end() ? it->second : 0;
        if (old_val != reg.second) {
            std::string reg_instr = guess_register_instruction(
                sim, old_val, reg.second, sim.reg_name(reg.first), init_regs, final_regs, virtual_rsp);
            if (!result.instr.empty()) result.instr += "; ";
            result.instr += reg_instr;
            assemble_instruction(reg_instr, result.machine_code);
        }
    }

    // If nothing changed
    if (result.instr.empty()) {
        result.instr = "nop";
        assemble_instruction("nop", result.machine_code);
    }

    return result;
}

// ---------------- Debug ----------------
void print_register_changes(Simulator& sim,
    const RegMap& init_regs,
    const RegMap& final_regs)
{
    std::cout << "--- Registers changed ---\n";
    for (auto& reg : final_regs) {
        auto it = init_regs.find(reg.first);
        if (it == init_regs.end() || it->second != reg.second) {
            std::cout << sim.reg_name(reg.first)
                << ": 0x" << std::hex << it->second
                << " -> 0x" << reg.second << "\n";
        }
    }
}

void print_memory_accesses(Simulator& sim) {
    std::cout << "--- Memory accesses ---\n";
    for (auto& m : sim.mem_accesses) {
        std::cout << (m.is_write ? "[WRITE] " : "[READ] ")
            << "0x" << std::hex << m.addr
            << " val=0x" << m.value;
        if (m.reg_src != -1)
            std::cout << " (from reg: " << Simulator::reg_name(m.reg_src) << ")";
        std::cout << "\n";
    }
}
