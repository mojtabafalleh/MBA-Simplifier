#pragma once
#include "simulator.h"
#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <cmath>
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
    snprintf(buf, sizeof(buf), "%llX", v);
    return std::string(buf);
}
std::string get_mem_name(uint64_t addr, const RegMap& regs, const std::vector<MemAccessModel>& accesses, size_t access_idx) {
    for (int reg_id : Simulator::TRACKED_REGS) {
        if (regs.find(reg_id) == regs.end()) continue;
        int64_t offset = static_cast<int64_t>(addr) - static_cast<int64_t>(regs.at(reg_id));
        if (std::abs(offset) < 0x1000) {
            std::string reg_name = Simulator::reg_name(reg_id);
            if (offset == 0) {
                return "mem[" + reg_name + "]";
            }
            std::string sign = (offset > 0) ? " + 0x" : " - 0x";
            return "mem[" + reg_name + sign + to_hex(std::abs(offset)) + "]";
        }
    }
    return "mem[0x" + to_hex(addr) + "]";
}
inline std::vector<Relation> find_constant_relations(
    Simulator& sim,
    const std::vector<uint8_t>& code,
    int trials = 5
) {
    std::vector<Relation> relations;
    std::vector<RegMap> inits(trials);
    std::vector<RegMap> final_regs(trials);
    std::vector<std::vector<MemAccessModel>> mem_accesses(trials);
    for (int t = 0; t < trials; ++t) {
        auto init = Simulator::make_random_regs();
        inits[t] = init;
        RegMap final;
        sim.emulate(code, init, final);
        final_regs[t] = final;
        std::vector<MemAccessModel> trial_mems;
        trial_mems.reserve(sim.mem_accesses.size());
        for (const auto& m : sim.mem_accesses) {
            trial_mems.push_back({ m.is_write, m.addr, m.value, m.reg_src });
        }
        mem_accesses[t] = std::move(trial_mems);
    }
    for (int reg_id : Simulator::TRACKED_REGS) {
        uint64_t const_val = final_regs[0][reg_id];
        bool is_constant = true;
        for (int t = 1; t < trials; ++t) {
            if (final_regs[t][reg_id] != const_val) {
                is_constant = false;
                break;
            }
        }
        if (is_constant && const_val != 0) {
            relations.push_back({ Simulator::reg_name(reg_id), "0x0", static_cast<int64_t>(const_val), true });
        }
    }
    for (int r1 : Simulator::TRACKED_REGS) {
        for (int r2 : Simulator::TRACKED_REGS) {
            if (r1 == r2) continue;
            int64_t delta = static_cast<int64_t>(final_regs[0][r1]) - static_cast<int64_t>(final_regs[0][r2]);
            bool stable = true;
            for (int t = 1; t < trials; ++t) {
                int64_t trial_delta = static_cast<int64_t>(final_regs[t][r1]) - static_cast<int64_t>(final_regs[t][r2]);
                if (trial_delta != delta) {
                    stable = false;
                    break;
                }
            }
            if (stable) {
                relations.push_back({ Simulator::reg_name(r1), Simulator::reg_name(r2), delta, true });
            }
        }
    }
    size_t num_accesses = mem_accesses[0].size();
    bool consistent_access_count = true;
    for (int t = 1; t < trials; ++t) {
        if (mem_accesses[t].size() != num_accesses) {
            consistent_access_count = false;
            break;
        }
    }
    if (!consistent_access_count) {
        return relations;
    }
    for (size_t idx = 0; idx < num_accesses; ++idx) {
        const auto& m0 = mem_accesses[0][idx];
        for (int reg_id : Simulator::TRACKED_REGS) {
            if (final_regs[0].find(reg_id) == final_regs[0].end()) continue;
            int64_t delta = static_cast<int64_t>(m0.value) - static_cast<int64_t>(final_regs[0][reg_id]);
            bool stable = true;
            bool type_consistent = m0.is_write;
            for (int t = 1; t < trials; ++t) {
                const auto& mt = mem_accesses[t][idx];
                if (mt.is_write != type_consistent) {
                    stable = false;
                    break;
                }
                int64_t trial_delta = static_cast<int64_t>(mt.value) - static_cast<int64_t>(final_regs[t][reg_id]);
                if (trial_delta != delta) {
                    stable = false;
                    break;
                }
            }
            if (stable) {
                std::string mem_name = get_mem_name(m0.addr, final_regs[0], mem_accesses[0], idx);
                bool consistent_base = true;
                for (int t = 1; t < trials; ++t) {
                    if (get_mem_name(mem_accesses[t][idx].addr, final_regs[t], mem_accesses[t], idx) != mem_name) {
                        consistent_base = false;
                        break;
                    }
                }
                if (!consistent_base) {
                    mem_name = "mem[unknown]";
                }
                if (type_consistent) {
                    relations.push_back({ mem_name, Simulator::reg_name(reg_id), delta, true });
                }
                else {
                    relations.push_back({ Simulator::reg_name(reg_id), mem_name, -delta, true });
                }
            }
        }
    }
    for (size_t i = 0; i < num_accesses; ++i) {
        for (size_t j = i + 1; j < num_accesses; ++j) {
            const auto& m1 = mem_accesses[0][i];
            const auto& m2 = mem_accesses[0][j];
            int64_t delta = static_cast<int64_t>(m1.value) - static_cast<int64_t>(m2.value);
            bool stable = true;
            for (int t = 1; t < trials; ++t) {
                const auto& it1 = mem_accesses[t][i];
                const auto& it2 = mem_accesses[t][j];
                if (it1.is_write != m1.is_write || it2.is_write != m2.is_write) {
                    stable = false;
                    break;
                }
                int64_t trial_delta = static_cast<int64_t>(it1.value) - static_cast<int64_t>(it2.value);
                if (trial_delta != delta) {
                    stable = false;
                    break;
                }
            }
            if (stable) {
                std::string lhs = get_mem_name(m1.addr, final_regs[0], mem_accesses[0], i);
                std::string rhs = get_mem_name(m2.addr, final_regs[0], mem_accesses[0], j);
                relations.push_back({ lhs, rhs, delta, true });
            }
        }
    }
    for (int reg_id : Simulator::TRACKED_REGS) {
        for (size_t idx = 0; idx < num_accesses; ++idx) {
            const auto& m0 = mem_accesses[0][idx];
            if (m0.is_write) continue;

            bool is_add = true;
            for (int t = 0; t < trials; ++t) {
                if (final_regs[t][reg_id] != inits[t][reg_id] + mem_accesses[t][idx].value) {
                    is_add = false;
                    break;
                }
            }
            if (is_add) {
                std::string mem_name = get_mem_name(m0.addr, final_regs[0], mem_accesses[0], idx);
                bool consistent = true;
                for (int t = 1; t < trials; ++t) {
                    if (get_mem_name(mem_accesses[t][idx].addr, final_regs[t], mem_accesses[t], idx) != mem_name) {
                        consistent = false;
                        break;
                    }
                }
                std::string rhs = "init_" + Simulator::reg_name(reg_id) + " + " + (consistent ? mem_name : "mem[unknown]");
                relations.push_back({ Simulator::reg_name(reg_id), rhs, 0, true });
                continue;
            }
            bool is_sub = true;
            for (int t = 0; t < trials; ++t) {
                if (final_regs[t][reg_id] != inits[t][reg_id] - mem_accesses[t][idx].value) {
                    is_sub = false;
                    break;
                }
            }
            if (is_sub) {
                std::string mem_name = get_mem_name(m0.addr, final_regs[0], mem_accesses[0], idx);
                bool consistent = true;
                for (int t = 1; t < trials; ++t) {
                    if (get_mem_name(mem_accesses[t][idx].addr, final_regs[t], mem_accesses[t], idx) != mem_name) {
                        consistent = false;
                        break;
                    }
                }
                std::string rhs = "init_" + Simulator::reg_name(reg_id) + " - " + (consistent ? mem_name : "mem[unknown]");
                relations.push_back({ Simulator::reg_name(reg_id), rhs, 0, true });
                continue;
            }
        }
    }
    return relations;
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
    for (const auto& r : result.relations) {
        if (!r.valid) continue;
        std::cout << r.lhs << " = " << r.rhs;
        if (r.delta > 0)
            std::cout << " + 0x" << std::hex << r.delta;
        else if (r.delta < 0)
            std::cout << " - 0x" << std::hex << (-r.delta);
        std::cout << std::dec << "\n";
    }
}