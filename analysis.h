#pragma once
#include "simulator.h"
#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <cmath>
#include <functional>

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

struct SimulationsData {
    std::vector<RegMap> inits;
    std::vector<RegMap> finals;
    std::vector<std::vector<MemAccessModel>> mem_accesses;
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

inline SimulationsData run_multiple_simulations(Simulator& sim, const std::vector<uint8_t>& code, int trials = 5) {
    SimulationsData data;
    data.inits.resize(trials);
    data.finals.resize(trials);
    data.mem_accesses.resize(trials);
    for (int t = 0; t < trials; ++t) {
        auto init = Simulator::make_random_regs();
        data.inits[t] = init;
        RegMap final;
        sim.emulate(code, init, final);
        data.finals[t] = final;
        std::vector<MemAccessModel> trial_mems;
        trial_mems.reserve(sim.mem_accesses.size());
        for (const auto& m : sim.mem_accesses) {
            trial_mems.push_back({ m.is_write, m.addr, m.value, m.reg_src });
        }
        data.mem_accesses[t] = std::move(trial_mems);
    }
    return data;
}

inline bool has_consistent_access_count(const SimulationsData& data) {
    size_t num_accesses = data.mem_accesses[0].size();
    for (size_t t = 1; t < data.inits.size(); ++t) {
        if (data.mem_accesses[t].size() != num_accesses) {
            return false;
        }
    }
    return true;
}

inline std::string get_consistent_mem_name(const SimulationsData& data, size_t idx) {
    std::string mem_name = get_mem_name(data.mem_accesses[0][idx].addr, data.inits[0], data.mem_accesses[0], idx);
    bool consistent = true;
    for (size_t t = 1; t < data.inits.size(); ++t) {
        if (get_mem_name(data.mem_accesses[t][idx].addr, data.inits[t], data.mem_accesses[t], idx) != mem_name) {
            consistent = false;
            break;
        }
    }
    return consistent ? mem_name : "mem[unknown]";
}

template<typename T, typename ComputeFunc>
bool is_value_stable(size_t trials, ComputeFunc compute, T& stable_value) {
    stable_value = compute(0);
    for (size_t t = 1; t < trials; ++t) {
        if (compute(t) != stable_value) {
            return false;
        }
    }
    return true;
}

template<typename PredFunc>
bool all_trials_satisfy(size_t trials, PredFunc pred) {
    for (size_t t = 0; t < trials; ++t) {
        if (!pred(t)) {
            return false;
        }
    }
    return true;
}

inline std::vector<Relation> find_reg_constants(const SimulationsData& data) {
    std::vector<Relation> relations;
    size_t trials = data.inits.size();
    for (int reg_id : Simulator::TRACKED_REGS) {
        if (data.finals[0].find(reg_id) == data.finals[0].end()) continue;
        uint64_t const_val;
        auto compute = [&](size_t t) {
            auto it = data.finals[t].find(reg_id);
            return (it != data.finals[t].end()) ? it->second : 0;
            };
        if (is_value_stable(trials, compute, const_val) && const_val != 0) {
            relations.push_back({ Simulator::reg_name(reg_id), "0x0", static_cast<int64_t>(const_val), true });
        }
    }
    return relations;
}

inline std::vector<Relation> find_reg_deltas(const SimulationsData& data) {
    std::vector<Relation> relations;
    size_t trials = data.inits.size();
    for (int reg_id : Simulator::TRACKED_REGS) {
        if (data.finals[0].find(reg_id) == data.finals[0].end() ||
            data.inits[0].find(reg_id) == data.inits[0].end()) continue;
        int64_t delta;
        auto compute = [&](size_t t) {
            auto final_it = data.finals[t].find(reg_id);
            auto init_it = data.inits[t].find(reg_id);
            if (final_it == data.finals[t].end() || init_it == data.inits[t].end()) {
                return int64_t(0);
            }
            return static_cast<int64_t>(final_it->second) - static_cast<int64_t>(init_it->second);
            };
        if (is_value_stable(trials, compute, delta) && delta != 0) {
            std::string reg_name = Simulator::reg_name(reg_id);
            relations.push_back({ reg_name, reg_name, delta, true });
        }
    }
    return relations;
}

inline std::vector<Relation> find_reg_pair_deltas(const SimulationsData& data) {
    std::vector<Relation> relations;
    size_t trials = data.inits.size();
    for (int r1 : Simulator::TRACKED_REGS) {
        if (data.finals[0].find(r1) == data.finals[0].end()) continue;
        for (int r2 : Simulator::TRACKED_REGS) {
            if (r1 == r2 || data.finals[0].find(r2) == data.finals[0].end()) continue;
            int64_t delta;
            auto compute = [&](size_t t) {
                auto r1_it = data.finals[t].find(r1);
                auto r2_it = data.finals[t].find(r2);
                if (r1_it == data.finals[t].end() || r2_it == data.finals[t].end()) {
                    return int64_t(0);
                }
                return static_cast<int64_t>(r1_it->second) - static_cast<int64_t>(r2_it->second);
                };
            if (is_value_stable(trials, compute, delta)) {
                relations.push_back({ Simulator::reg_name(r1), Simulator::reg_name(r2), delta, true });
            }
        }
    }
    return relations;
}

inline std::vector<Relation> find_mem_reg_relations(const SimulationsData& data) {
    std::vector<Relation> relations;
    size_t trials = data.inits.size();
    size_t num_accesses = data.mem_accesses[0].size();
    for (size_t idx = 0; idx < num_accesses; ++idx) {
        bool type_consistent = data.mem_accesses[0][idx].is_write;
        bool types_stable = true;
        for (size_t t = 1; t < trials; ++t) {
            if (data.mem_accesses[t][idx].is_write != type_consistent) {
                types_stable = false;
                break;
            }
        }
        if (!types_stable) continue;
        for (int reg_id : Simulator::TRACKED_REGS) {
            if (data.finals[0].find(reg_id) == data.finals[0].end()) continue;
            int64_t delta;
            auto compute = [&](size_t t) {
                auto reg_it = data.finals[t].find(reg_id);
                if (reg_it == data.finals[t].end()) {
                    return int64_t(0);
                }
                return static_cast<int64_t>(data.mem_accesses[t][idx].value) -
                    static_cast<int64_t>(reg_it->second);
                };
            if (is_value_stable(trials, compute, delta)) {
                std::string mem_name = get_consistent_mem_name(data, idx);
                std::string reg_name = Simulator::reg_name(reg_id);
                if (type_consistent) {
                    relations.push_back({ mem_name, reg_name, delta, true });
                }
                else {
                    relations.push_back({ reg_name, mem_name, -delta, true });
                }
            }
        }
    }
    return relations;
}

inline std::vector<Relation> find_mem_pair_deltas(const SimulationsData& data) {
    std::vector<Relation> relations;
    size_t trials = data.inits.size();
    size_t num_accesses = data.mem_accesses[0].size();
    for (size_t i = 0; i < num_accesses; ++i) {
        for (size_t j = i + 1; j < num_accesses; ++j) {
            bool types_stable = true;
            bool type_i = data.mem_accesses[0][i].is_write;
            bool type_j = data.mem_accesses[0][j].is_write;
            for (size_t t = 1; t < trials; ++t) {
                if (data.mem_accesses[t][i].is_write != type_i || data.mem_accesses[t][j].is_write != type_j) {
                    types_stable = false;
                    break;
                }
            }
            if (!types_stable) continue;
            int64_t delta;
            auto compute = [&](size_t t) {
                return static_cast<int64_t>(data.mem_accesses[t][i].value) - static_cast<int64_t>(data.mem_accesses[t][j].value);
                };
            if (is_value_stable(trials, compute, delta)) {
                std::string lhs = get_consistent_mem_name(data, i);
                std::string rhs = get_consistent_mem_name(data, j);
                relations.push_back({ lhs, rhs, delta, true });
            }
        }
    }
    return relations;
}

inline std::vector<Relation> find_reg_mem_operations(const SimulationsData& data) {
    std::vector<Relation> relations;
    size_t trials = data.inits.size();
    size_t num_accesses = data.mem_accesses[0].size();
    for (int reg_id : Simulator::TRACKED_REGS) {
        if (data.finals[0].find(reg_id) == data.finals[0].end() ||
            data.inits[0].find(reg_id) == data.inits[0].end()) continue;
        for (size_t idx = 0; idx < num_accesses; ++idx) {
            if (data.mem_accesses[0][idx].is_write) continue;
            std::string reg_name = Simulator::reg_name(reg_id);
            std::string mem_name = get_consistent_mem_name(data, idx);

  
            auto pred_mov = [&](size_t t) {
                auto reg_it = data.finals[t].find(reg_id);
                return reg_it != data.finals[t].end() &&
                    reg_it->second == data.mem_accesses[t][idx].value;
                };
            if (all_trials_satisfy(trials, pred_mov)) {
                relations.push_back({ reg_name, mem_name, 0, true });
                continue;
            }

            auto pred_add = [&](size_t t) {
                auto final_it = data.finals[t].find(reg_id);
                auto init_it = data.inits[t].find(reg_id);
                return final_it != data.finals[t].end() &&
                    init_it != data.inits[t].end() &&
                    final_it->second == init_it->second + data.mem_accesses[t][idx].value;
                };
            if (all_trials_satisfy(trials, pred_add)) {
                std::string rhs = "init_" + reg_name + " + " + mem_name;
                relations.push_back({ reg_name, rhs, 0, true });
                continue;
            }


            auto pred_sub = [&](size_t t) {
                auto final_it = data.finals[t].find(reg_id);
                auto init_it = data.inits[t].find(reg_id);
                return final_it != data.finals[t].end() &&
                    init_it != data.inits[t].end() &&
                    final_it->second == init_it->second - data.mem_accesses[t][idx].value;
                };
            if (all_trials_satisfy(trials, pred_sub)) {
                std::string rhs = "init_" + reg_name + " - " + mem_name;
                relations.push_back({ reg_name, rhs, 0, true });
                continue;
            }
        }
    }
    return relations;
}

inline std::vector<Relation> find_constant_relations(
    Simulator& sim,
    const std::vector<uint8_t>& code,
    int trials = 5
) {
    auto data = run_multiple_simulations(sim, code, trials);
    std::vector<Relation> relations;
    if (!has_consistent_access_count(data)) {
        return relations;
    }

    auto append = [&](const auto& rels) {
        relations.insert(relations.end(), rels.begin(), rels.end());
        };

    append(find_reg_constants(data));
    append(find_reg_deltas(data));
    append(find_reg_pair_deltas(data));
    append(find_mem_reg_relations(data));
    append(find_mem_pair_deltas(data));
    append(find_reg_mem_operations(data));

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