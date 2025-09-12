#pragma once
#include "simulator.h"
#include <iostream>
#include <vector>
#include <string>
#include <set>

struct RegChange {
    std::string name;
    uint64_t old_val;
    uint64_t new_val;
};

struct MemAccessModel {
    bool is_write;
    uint64_t addr;
    uint64_t value;
    int reg_src;   
};

struct Relation {
    std::string lhs;   
    std::string rhs;   
    int64_t delta;   
    bool valid;
};


struct ExecutionResult {
    std::vector<RegChange> reg_changes;
    std::vector<MemAccessModel> mem_accesses;
    std::vector<Relation> relations;   
};
inline std::string to_hex(uint64_t v) {
    char buf[32];
    sprintf(buf, "%llX", v);
    return std::string(buf);
}
inline std::vector<Relation> find_constant_relations(
    Simulator& sim,
    const std::vector<uint8_t>& code,
    int trials = 5
) {
    std::vector<Relation> out;
    std::vector<RegMap> finals(trials);
    std::vector<std::vector<MemAccessModel>> mems(trials);

    for (int t = 0; t < trials; t++) {
        auto init = Simulator::make_random_regs();
        RegMap final;
        sim.emulate(code, init, final);
        finals[t] = final;

        std::vector<MemAccessModel> mem_copy;
        for (auto& m : sim.mem_accesses)
            mem_copy.push_back({ m.is_write, m.addr, m.value, m.reg_src });
        mems[t] = mem_copy;
    }

    for (int r : Simulator::TRACKED_REGS) {
        bool stable = true;
        int64_t delta0 = (int64_t)finals[0][r] - (int64_t)finals[0][r];
        for (int t = 1; t < trials; t++) {
            int64_t delta = (int64_t)finals[t][r] - (int64_t)finals[t][r];
            if (delta != delta0) {
                stable = false;
                break;
            }
        }
        if (stable && delta0 != 0)
            out.push_back({ Simulator::reg_name(r), "0x0", delta0, true });
    }

    for (int r1 : Simulator::TRACKED_REGS) {
        for (int r2 : Simulator::TRACKED_REGS) {
            if (r1 == r2) continue;
            bool stable = true;
            int64_t delta0 = (int64_t)finals[0][r1] - (int64_t)finals[0][r2];
            for (int t = 1; t < trials; t++) {
                int64_t delta = (int64_t)finals[t][r1] - (int64_t)finals[t][r2];
                if (delta != delta0) {
                    stable = false;
                    break;
                }
            }
            if (stable)
                out.push_back({ Simulator::reg_name(r1), Simulator::reg_name(r2), delta0, true });
        }
    }

    for (size_t i = 0; i < mems[0].size(); i++) {
        auto& m0 = mems[0][i];
        if (m0.reg_src == -1) continue;
        bool stable = true;
        int64_t delta0 = (int64_t)m0.value - (int64_t)finals[0][m0.reg_src];
        for (int t = 1; t < trials; t++) {
            auto it = std::find_if(mems[t].begin(), mems[t].end(), [&](const MemAccessModel& x) { return x.addr == m0.addr; });
            if (it == mems[t].end()) { stable = false; break; }
            int64_t delta = (int64_t)it->value - (int64_t)finals[t][it->reg_src];
            if (delta != delta0) { stable = false; break; }
        }
        if (stable) {
            int64_t rsp_offset = (int64_t)m0.addr - (int64_t)finals[0][UC_X86_REG_RSP];
            std::string lhs = (rsp_offset >= 0 && rsp_offset < 0x1000) ? "mem[RSP + 0x" + to_hex(rsp_offset) + "]" : "mem[0x" + to_hex(m0.addr) + "]";
            out.push_back({ lhs, Simulator::reg_name(m0.reg_src), delta0, true });
        }
    }

    for (size_t i = 0; i < mems[0].size(); i++) {
        for (size_t j = i + 1; j < mems[0].size(); j++) {
            auto& m1 = mems[0][i];
            auto& m2 = mems[0][j];
            bool stable = true;
            int64_t delta0 = (int64_t)m1.value - (int64_t)m2.value;
            for (int t = 1; t < trials; t++) {
                auto it1 = std::find_if(mems[t].begin(), mems[t].end(), [&](const MemAccessModel& x) { return x.addr == m1.addr; });
                auto it2 = std::find_if(mems[t].begin(), mems[t].end(), [&](const MemAccessModel& x) { return x.addr == m2.addr; });
                if (it1 == mems[t].end() || it2 == mems[t].end()) { stable = false; break; }
                int64_t delta = (int64_t)it1->value - (int64_t)it2->value;
                if (delta != delta0) { stable = false; break; }
            }
            if (stable) {
                std::string lhs = "mem[0x" + to_hex(m1.addr) + "]";
                std::string rhs = "mem[0x" + to_hex(m2.addr) + "]";
                out.push_back({ lhs, rhs, delta0, true });
            }
        }
    }

    return out;
}






ExecutionResult analyze_execution(Simulator& sim,
    const std::vector<uint8_t>& code,
    const RegMap& init_regs,
    const RegMap& final_regs)
{
    ExecutionResult result;


    for (auto& reg : final_regs) {
        auto it = init_regs.find(reg.first);
        uint64_t old_val = (it != init_regs.end()) ? it->second : 0;
        if (it == init_regs.end() || old_val != reg.second) {
            result.reg_changes.push_back({
                sim.reg_name(reg.first),
                old_val,
                reg.second
                });
        }
    }


    for (auto& m : sim.mem_accesses) {
        result.mem_accesses.push_back({
            m.is_write,
            m.addr,
            m.value,
            m.reg_src
            });
    }

    result.relations = find_constant_relations(sim, code, 5);

    return result;
}


inline void print_register_changes(const ExecutionResult& result) {
    std::cout << "--- Registers changed ---\n";
    for (auto& rc : result.reg_changes) {
        std::cout << rc.name << ": 0x" << std::hex << rc.old_val
            << " -> 0x" << rc.new_val << "\n";
    }
}


inline void print_memory_accesses(const ExecutionResult& result) {
    std::cout << "--- Memory accesses ---\n";
    for (auto& ma : result.mem_accesses) {
        std::cout << (ma.is_write ? "[WRITE] " : "[READ] ")
            << "0x" << std::hex << ma.addr
            << " val=0x" << ma.value;
        if (ma.reg_src != -1)
            std::cout << " (from reg: " << Simulator::reg_name(ma.reg_src) << ")";
        std::cout << "\n";
    }
}
inline void print_relations(const ExecutionResult& result) {
    std::cout << "--- Constant relations ---\n";
    for (auto& r : result.relations) {
        if (!r.valid) continue;

        std::cout << r.lhs << " = " << r.rhs;

        if (r.delta > 0)
            std::cout << " + 0x" << std::hex << r.delta;
        else if (r.delta < 0)
            std::cout << " - 0x" << std::hex << (-r.delta);

        std::cout << std::dec << "\n";
    }
}

