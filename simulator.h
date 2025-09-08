#pragma once
#include <unicorn/unicorn.h>
#include <vector>
#include <map>
#include <cstdint>
#include <string>
#include <random>
#include <iostream>
#include <sstream>

struct MemAccess {
    uint64_t addr;
    int size;
    uint64_t ip;
    uint64_t value;
    bool is_write;
    int reg_src;
};

using RegMap = std::map<int, uint64_t>;

std::string hex_str(uint64_t val) {
    std::stringstream ss;
    ss << std::hex << val;
    return ss.str();
}

class Simulator {
public:
    std::vector<MemAccess> mem_accesses;
    RegMap last_regs_in;
    uint64_t current_ip = 0;

    static const std::vector<int> TRACKED_REGS;

    static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
            bytes.push_back((uint8_t)strtol(hex.substr(i, 2).c_str(), nullptr, 16));
        return bytes;
    }

    static std::string reg_name(int r) {
        switch (r) {
        case UC_X86_REG_RAX: return "RAX"; case UC_X86_REG_RBX: return "RBX";
        case UC_X86_REG_RCX: return "RCX"; case UC_X86_REG_RDX: return "RDX";
        case UC_X86_REG_RSI: return "RSI"; case UC_X86_REG_RDI: return "RDI";
        case UC_X86_REG_RSP: return "RSP"; case UC_X86_REG_RBP: return "RBP";
        case UC_X86_REG_R8: return "R8"; case UC_X86_REG_R9: return "R9";
        case UC_X86_REG_R10: return "R10"; case UC_X86_REG_R11: return "R11";
        case UC_X86_REG_R12: return "R12"; case UC_X86_REG_R13: return "R13";
        case UC_X86_REG_R14: return "R14"; case UC_X86_REG_R15: return "R15";
        default: return "UNK";
        }
    }

    static RegMap make_random_regs() {
        RegMap regs;
        std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<uint64_t> dist(0x100000000ULL, 0x1FFFFFFFFULL);
        for (int r : TRACKED_REGS) regs[r] = dist(rng);
        return regs;
    }

    static void write_regs(uc_engine* uc, const RegMap& regs) {
        for (auto& p : regs) { uint64_t v = p.second; uc_reg_write(uc, p.first, &v); }
    }

    static RegMap read_regs(uc_engine* uc) {
        RegMap out;
        for (int r : TRACKED_REGS) { uint64_t v = 0; uc_reg_read(uc, r, &v); out[r] = v; }
        return out;
    }

    bool emulate(const std::vector<uint8_t>& code, const RegMap& init_regs, RegMap& final_regs) {
        uc_engine* uc;
        if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc) != UC_ERR_OK) return false;

        const uint64_t ADDR = 0x1000000ULL;
        uc_mem_map(uc, ADDR, 2 * 1024 * 1024, UC_PROT_ALL);
        uc_mem_write(uc, ADDR, code.data(), code.size());

        last_regs_in = init_regs;
        write_regs(uc, init_regs);
        mem_accesses.clear();
        current_ip = 0;

        uc_hook h_r, h_w, h_inv;
        uc_hook_add(uc, &h_r, UC_HOOK_MEM_READ, (void*)hook_mem_read, this, 1, 0);
        uc_hook_add(uc, &h_w, UC_HOOK_MEM_WRITE, (void*)hook_mem_write, this, 1, 0);
        uc_hook_add(uc, &h_inv, UC_HOOK_MEM_INVALID, (void*)hook_mem_invalid, this, 1, 0);

        uc_emu_start(uc, ADDR, ADDR + code.size(), 0, 0);

        final_regs = read_regs(uc);
        uc_close(uc);
        return true;
    }

private:
    static void hook_mem_write(uc_engine*, uc_mem_type, uint64_t addr, int size, int64_t value, void* user) {
        auto sim = static_cast<Simulator*>(user);
        int reg_src = -1;
        for (auto& r : sim->last_regs_in) if ((uint64_t)value == r.second) { reg_src = r.first; break; }
        sim->mem_accesses.push_back({ addr, size, sim->current_ip, (uint64_t)value, true, reg_src });
    }

    static void hook_mem_read(uc_engine* uc, uc_mem_type, uint64_t addr, int size, int64_t, void* user) {
        auto sim = static_cast<Simulator*>(user);
        int reg_src = -1;
        for (auto it = sim->mem_accesses.rbegin(); it != sim->mem_accesses.rend(); ++it) {
            if (it->is_write && it->addr == addr) { reg_src = it->reg_src; break; }
        }
        uint64_t val = 0;
        uc_mem_read(uc, addr, &val, size);
        sim->mem_accesses.push_back({ addr, size, sim->current_ip, val, false, reg_src });
    }

    static bool hook_mem_invalid(uc_engine* uc, uc_mem_type, uint64_t addr, int, int64_t, void* user) {
        const uint64_t PAGE = 0x1000;
        uint64_t base = addr & ~(PAGE - 1);
        uc_mem_map(uc, base, PAGE, UC_PROT_ALL);

        std::mt19937 rng(12345);
        std::uniform_int_distribution<uint32_t> dist(0, 255);
        std::vector<uint8_t> random_page(PAGE);
        for (auto& b : random_page) b = static_cast<uint8_t>(dist(rng));
        uc_mem_write(uc, base, random_page.data(), random_page.size());
        return true;
    }
};

const std::vector<int> Simulator::TRACKED_REGS = {
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RSP, UC_X86_REG_RBP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15
};


enum class TestMode {
    RANDOM_REGS,
    FIXED_REGS,
    SINGLE_CHANGE
};

struct TestResult {
    bool match;
    RegMap regs_original;
    RegMap regs_predicted;
};

class InstructionTester {
public:
    static TestResult test_equivalence(
        const std::vector<uint8_t>& original_code,
        const std::vector<uint8_t>& predicted_code,
        TestMode mode,
        int changed_reg = UC_X86_REG_RAX
    ) {
        Simulator sim1, sim2;
        RegMap init_regs;

        switch (mode) {
        case TestMode::RANDOM_REGS:
            init_regs = Simulator::make_random_regs();
            break;
        case TestMode::FIXED_REGS:
            for (int r : Simulator::TRACKED_REGS) init_regs[r] = 0x1111111111111111ULL;
            break;
        case TestMode::SINGLE_CHANGE:
            init_regs = Simulator::make_random_regs();
            init_regs[changed_reg] ^= 0x1234ULL;
            break;
        }

        RegMap out1, out2;
        sim1.emulate(original_code, init_regs, out1);
        sim2.emulate(predicted_code, init_regs, out2);

        bool same = compare_regs(out1, out2);
        return { same, out1, out2 };
    }

private:
    static bool compare_regs(const RegMap& a, const RegMap& b) {
        for (auto& r : Simulator::TRACKED_REGS) {
            if (a.at(r) != b.at(r)) return false;
        }
        return true;
    }
};
