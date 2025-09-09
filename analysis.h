#include "simulator.h"
#include "deps/XEDParse.h"
#include <iostream>
#include <cstring>
#include <vector>
#include <sstream>
#include <cmath>
#include <memory>
constexpr int REG_RIP_FAKE = -2;

struct MemorySymbol {
    uint64_t addr;
    int base_reg;
    int64_t disp;
    std::string repr;
    uint64_t value;
};
struct GuessResult {
    std::string instr;
    std::vector<uint8_t> machine_code;
};

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

bool handle_rsp_change(Simulator& sim, uint64_t& virtual_rsp,
    uint64_t old_rsp, uint64_t new_rsp,
    const RegMap& init_regs,
    std::string& instr, std::vector<uint8_t>& machine_code)
{
    if (old_rsp == new_rsp) return false;
    std::string guessed_instr;
    for (auto& r : init_regs) {
        if (r.first != UC_X86_REG_RSP && r.second == new_rsp) {
            guessed_instr = "mov rsp," + sim.reg_name(r.first);
            break;
        }
    }
    if (guessed_instr.empty()) {
        int64_t diff = static_cast<int64_t>(new_rsp) - static_cast<int64_t>(old_rsp);
        if (diff > 0 && diff < 0x1000) guessed_instr = "add rsp, 0x" + to_hex(diff);
        else if (diff < 0 && -diff < 0x1000) guessed_instr = "sub rsp, 0x" + to_hex(-diff);
        else if (diff >= -0x8000 && diff <= 0x7FFF) guessed_instr = "lea rsp, [rsp" + to_hex_signed(diff) + "]";
        else guessed_instr = "mov rsp,0x" + to_hex(new_rsp);
    }
    assemble_instruction(guessed_instr, machine_code);
    instr = guessed_instr;
    virtual_rsp = new_rsp;
    return true;
}


std::vector<MemorySymbol> build_memory_symbols(Simulator& sim,
    const std::vector<MemAccess>& mem_accesses,
    const RegMap& init_regs,
    const RegMap& final_regs)
{
    std::vector<MemorySymbol> syms;
    auto try_from_regs = [&](uint64_t addr, const RegMap& regs) -> MemorySymbol {
        for (auto& r : regs) {
            int reg_id = r.first;
            uint64_t reg_val = r.second;
            int64_t disp = static_cast<int64_t>(addr) - static_cast<int64_t>(reg_val);
            if (disp >= -0x8000 && disp <= 0x7FFF) {
                MemorySymbol ms;
                ms.addr = addr;
                ms.base_reg = reg_id;
                ms.disp = disp;
                std::ostringstream oss;
                oss << "[" << sim.reg_name(reg_id);
                if (disp > 0) oss << "+0x" << std::hex << disp;
                else if (disp < 0) oss << "-0x" << std::hex << -disp;
                oss << "]";
                ms.repr = oss.str();
                ms.value = 0;
                return ms;
            }
        }
        return MemorySymbol{ 0, -1, 0, std::string(), 0 };
        };
    for (auto& m : mem_accesses) {
        if (m.is_write) continue;
        MemorySymbol ms = try_from_regs(m.addr, init_regs);
        if (ms.base_reg == -1) ms = try_from_regs(m.addr, final_regs);
        if (ms.base_reg != -1) {
            ms.value = m.value;
            syms.push_back(ms);
            continue;
        }
        if (m.reg_src != -1) {
            MemorySymbol ms2;
            ms2.addr = m.addr;
            ms2.base_reg = m.reg_src;
            ms2.disp = 0;
            ms2.repr = std::string("[") + sim.reg_name(m.reg_src) + "]";
            ms2.value = m.value;
            syms.push_back(ms2);
        }
        int64_t disp = static_cast<int64_t>(m.addr) - static_cast<int64_t>(sim.current_ip);
        if (disp >= INT32_MIN && disp <= INT32_MAX) {
            MemorySymbol ms_rip;
            ms_rip.addr = m.addr;
            ms_rip.base_reg = REG_RIP_FAKE;
            ms_rip.disp = disp;
            std::ostringstream oss;
            oss << "[rip";
            if (disp > 0) oss << "+0x" << std::hex << disp;
            else if (disp < 0) oss << "-0x" << std::hex << -disp;
            oss << "]";
            ms_rip.repr = oss.str();
            ms_rip.value = m.value;
            syms.push_back(ms_rip);
            continue;
        }
    }
    std::vector<MemorySymbol> dedup;
    for (auto& s : syms) {
        bool found = false;
        for (auto& d : dedup) if (d.addr == s.addr) { found = true; break; }
        if (!found) dedup.push_back(s);
    }
    return dedup;
}

std::string guess_memory_write(Simulator& sim,
    const std::vector<MemAccess>& mem_accesses,
    const RegMap& init_regs,
    const RegMap& final_regs,
    const std::vector<MemorySymbol>& mem_syms)
{
    for (auto& m : mem_accesses) {
        if (!m.is_write) continue;
        if (m.reg_src == -1) continue;
        std::string src = sim.reg_name(m.reg_src);
        for (auto& r : init_regs) {
            if (r.second == m.addr) {
                return "mov qword ptr [" + sim.reg_name(r.first) + "]," + src;
            }
        }
        for (auto& r : final_regs) {
            if (r.second == m.addr) {
                return "mov qword ptr [" + sim.reg_name(r.first) + "]," + src;
            }
        }
        for (auto& ms : mem_syms) {
            if (ms.addr == m.addr) {
                return "mov qword ptr " + ms.repr + "," + src;
            }
        }
        auto try_base_disp = [&](const RegMap& regs) -> std::string {
            for (auto& r : regs) {
                int64_t disp = static_cast<int64_t>(m.addr) - static_cast<int64_t>(r.second);
                if (disp >= -0x8000 && disp <= 0x7FFF) {
                    std::string base = sim.reg_name(r.first);
                    std::ostringstream oss;
                    oss << "mov qword ptr [" << base;
                    if (disp > 0) oss << "+0x" << std::hex << disp;
                    else if (disp < 0) oss << "-0x" << std::hex << (-disp);
                    oss << "]," << src;
                    return oss.str();
                }
            }
            return "";
            };
        std::string bd = try_base_disp(init_regs);
        if (!bd.empty()) return bd;
        bd = try_base_disp(final_regs);
        if (!bd.empty()) return bd;
    }
    return "";
}

std::string guess_register_instruction(Simulator& sim,
    uint64_t old_val, uint64_t new_val,
    const std::string& reg_name,
    const RegMap& init_regs,
    const RegMap& final_regs,
    uint64_t virtual_rsp,
    const std::vector<MemorySymbol>& mem_syms)
{
    if (new_val == 0) return "xor " + reg_name + "," + reg_name;
    for (auto& r : init_regs) {
        if (r.second == new_val && sim.reg_name(r.first) != reg_name) {
            return "mov " + reg_name + "," + sim.reg_name(r.first);
        }
    }
    for (auto& m : sim.mem_accesses) {
        if (m.is_write) continue;
        if (m.value != new_val) continue;
        if (m.reg_src != -1) {
            return "mov " + reg_name + ",[" + sim.reg_name(m.reg_src) + "]";
        }
        for (auto& r : init_regs) {
            if (r.second == m.addr) {
                if (sim.reg_name(r.first) != reg_name) return "mov " + reg_name + ",[" + sim.reg_name(r.first) + "]";
            }
        }
        for (auto& r : final_regs) {
            if (r.second == m.addr) {
                if (sim.reg_name(r.first) != reg_name) return "mov " + reg_name + ",[" + sim.reg_name(r.first) + "]";
            }
        }
        auto try_base_disp = [&](const RegMap& regs) -> std::string {
            for (auto& r : regs) {
                int64_t disp = static_cast<int64_t>(m.addr) - static_cast<int64_t>(r.second);
                if (disp >= -0x8000 && disp <= 0x7FFF) {
                    std::string base = sim.reg_name(r.first);
                    std::string memop = "mov " + reg_name + ",[" + base;
                    if (disp > 0) memop += "+" + std::string("0x") + to_hex(static_cast<uint64_t>(disp));
                    else if (disp < 0) {
                        int64_t absdisp = -disp;
                        memop += "-" + std::string("0x") + to_hex(static_cast<uint64_t>(absdisp));
                    }
                    memop += "]";
                    return memop;
                }
            }
            return std::string();
            };
        std::string bd = try_base_disp(init_regs);
        if (!bd.empty()) return bd;
        bd = try_base_disp(final_regs);
        if (!bd.empty()) return bd;
    }
    for (const auto& ms : mem_syms) {
        if (ms.value == new_val) return "mov " + reg_name + "," + ms.repr;
        if (static_cast<uint64_t>(static_cast<int64_t>(old_val) + static_cast<int64_t>(ms.value)) == new_val) {
            return "add " + reg_name + ", qword ptr " + ms.repr;
        }
        if (static_cast<uint64_t>(static_cast<int64_t>(old_val) - static_cast<int64_t>(ms.value)) == new_val) {
            return "sub " + reg_name + ", qword ptr " + ms.repr;
        }
    }
    int64_t diff = static_cast<int64_t>(new_val) - static_cast<int64_t>(old_val);
    if (diff == 1) return "inc " + reg_name;
    if (diff == -1) return "dec " + reg_name;
    if (diff > 0 && diff < 0x1000) return "add " + reg_name + ",0x" + to_hex(diff);
    if (diff < 0 && -diff < 0x1000) return "sub " + reg_name + ",0x" + to_hex(-diff);
    for (int i = 1; i <= 63; i++) {
        if ((int64_t)new_val == ((int64_t)old_val >> i)) return "sar " + reg_name + ",0x" + to_hex(i);
    }
    auto ror = [](uint64_t val, int n) {
        return (val >> n) | (val << (64 - n));
        };
    for (int i = 1; i < 64; i++) {
        if (new_val == ror(old_val, i)) return "ror " + reg_name + ",0x" + to_hex(i);
    }
    return "mov " + reg_name + ",0x" + to_hex(new_val);
}


GuessResult guess_instruction(Simulator& sim,
    const RegMap& init_regs,
    const RegMap& final_regs)
{
    GuessResult result;
    uint64_t virtual_rsp = init_regs.at(UC_X86_REG_RSP);
    auto rsp_final_it = final_regs.find(UC_X86_REG_RSP);
    if (rsp_final_it != final_regs.end() && rsp_final_it->second != virtual_rsp) {
        handle_rsp_change(sim, virtual_rsp, virtual_rsp, rsp_final_it->second, final_regs, result.instr, result.machine_code);
    }
    auto mem_syms = build_memory_symbols(sim, sim.mem_accesses, init_regs, final_regs);
    for (auto& reg : final_regs) {
        if (reg.first == UC_X86_REG_RSP) continue;
        auto it = init_regs.find(reg.first);
        uint64_t old_val = it != init_regs.end() ? it->second : 0;
        if (old_val != reg.second) {
            std::string reg_instr = guess_register_instruction(
                sim, old_val, reg.second, sim.reg_name(reg.first), init_regs, final_regs, virtual_rsp, mem_syms);
            if (!result.instr.empty()) result.instr += "; ";
            result.instr += reg_instr;
            assemble_instruction(reg_instr, result.machine_code);
        }
    }
    if (result.instr.empty()) {
        std::string mem_instr = guess_memory_write(sim, sim.mem_accesses, init_regs, final_regs, mem_syms);
        if (!mem_instr.empty()) {
            result.instr = mem_instr;
            assemble_instruction(mem_instr, result.machine_code);
        }
    }
    if (result.instr.empty()) {
        result.instr = "nop";
        assemble_instruction("nop", result.machine_code);
    }
    return result;
}

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
