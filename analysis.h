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
    std::set<std::string> seen_relations;

    for (int r : Simulator::TRACKED_REGS) {
        bool first = true;
        int64_t expected_delta = 0;
        bool stable = true;

        for (int t = 0; t < trials; t++) {
            auto init = Simulator::make_random_regs();
            RegMap final;
            sim.emulate(code, init, final);

            int64_t diff = (int64_t)final[r] - (int64_t)init[r];
            if (first) {
                expected_delta = diff;
                first = false;
            }
            else if (expected_delta != diff) {
                stable = false;
                break;
            }
        }

        if (!first && stable && expected_delta != 0) {
            out.push_back({
                Simulator::reg_name(r),
                "0x0",
                expected_delta,
                true
                });
        }
    }


    for (int r1 : Simulator::TRACKED_REGS) {
        for (int r2 : Simulator::TRACKED_REGS) {
            if (r1 == r2) continue;

            bool first = true;
            int64_t expected_delta = 0;
            bool stable = true;

            for (int t = 0; t < trials; t++) {
                auto init = Simulator::make_random_regs();
                RegMap final;
                sim.emulate(code, init, final);

                int64_t diff = (int64_t)final[r1] - (int64_t)final[r2];
                if (first) {
                    expected_delta = diff;
                    first = false;
                }
                else if (expected_delta != diff) {
                    stable = false;
                    break;
                }
            }

            if (!first && stable) {
                out.push_back({
                    Simulator::reg_name(r1),
                    Simulator::reg_name(r2),
                    expected_delta,
                    true
                    });
            }
        }
    }




    for (int t = 0; t < trials; t++) {
        auto init = Simulator::make_random_regs();
        RegMap final;
        sim.emulate(code, init, final);

        for (auto& m : sim.mem_accesses) {
            if (m.reg_src != -1) {
                int64_t diff = (int64_t)m.value - (int64_t)final[m.reg_src];

   
                int64_t rsp_offset = (int64_t)m.addr - (int64_t)final[UC_X86_REG_RSP];
                std::string lhs;
                if (rsp_offset >= 0 && rsp_offset < 0x1000) {
                    lhs = "mem[RSP + 0x" + to_hex(rsp_offset) + "]";
                }
                else {
                    lhs = "mem[0x" + to_hex(m.addr) + "]";
                }

                std::string key = lhs + "=" + Simulator::reg_name(m.reg_src) + "+" + std::to_string(diff);
                if (seen_relations.find(key) == seen_relations.end()) {
                    out.push_back({
                        lhs,
                        Simulator::reg_name(m.reg_src),
                        diff,
                        true
                        });
                    seen_relations.insert(key);
                }
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

