#pragma once
#include "simulator.h"
#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <functional>

/**
 * @brief Represents a change in a CPU register during execution.
 * Example: rax changed from 0x0 -> 0x42
 */
struct RegisterChange {
    std::string name;
    uint64_t old_value;
    uint64_t new_value;
};

/**
 * @brief Represents a memory access (read or write) during execution.
 * Example: write 0x1000 <- 0x42 from rax
 */
struct MemoryAccess {
    bool is_write;
    uint64_t address;
    uint64_t value;
    int source_reg; // register id that generated the access, -1 if unknown
};

/**
 * @brief Represents a constant or delta relationship between registers/memory.
 * Example: rax = rbx + 0x8
 */
struct Relation {
    std::string lhs;
    std::string rhs;
    int64_t delta;
    bool valid;
};

/**
 * @brief Stores the result of a single execution analysis.
 */
struct ExecutionResult {
    std::vector<RegisterChange> reg_changes;
    std::vector<MemoryAccess> mem_accesses;
    std::vector<Relation> relations;
};

/**
 * @brief Stores multiple trials of simulation data.
 */
struct SimulationData {
    std::vector<RegMap> initial_regs;
    std::vector<RegMap> final_regs;
    std::vector<std::vector<MemoryAccess>> memory_accesses;
};

/**
 * @brief Converts a 64-bit value to a hexadecimal string.
 * Example: 42 -> "2A"
 */
inline std::string to_hex(uint64_t value) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%llX", value);
    return std::string(buf);
}

/**
 * @brief Returns a human-readable memory name based on tracked registers.
 * Example: If rax=0x1000 and addr=0x1004 -> "mem[rax + 0x4]"
 */
inline std::string get_memory_name(uint64_t addr, const RegMap& regs) {
    for (int reg_id : Simulator::TRACKED_REGS) {
        if (regs.find(reg_id) == regs.end()) continue;
        int64_t offset = static_cast<int64_t>(addr) - static_cast<int64_t>(regs.at(reg_id));
        if (std::abs(offset) < 0x1000) {
            std::string reg_name = Simulator::reg_name(reg_id);
            if (offset == 0) return "mem[" + reg_name + "]";
            return "mem[" + reg_name + (offset > 0 ? " + 0x" : " - 0x") + to_hex(std::abs(offset)) + "]";
        }
    }
    return "mem[0x" + to_hex(addr) + "]";
}

/**
 * @brief Runs multiple trials of simulation with random initial registers.
 * Stores initial/final registers and memory accesses.
 * Example: run_simulations(sim, code, 5) -> 5 trial results
 */
inline SimulationData run_simulations(Simulator& sim, const std::vector<uint8_t>& code, int trials = 5) {
    SimulationData data;
    data.initial_regs.resize(trials);
    data.final_regs.resize(trials);
    data.memory_accesses.resize(trials);

    for (int t = 0; t < trials; ++t) {
        RegMap initial = Simulator::make_random_regs();
        data.initial_regs[t] = initial;
        RegMap final_state;
        sim.emulate(code, initial, final_state);
        data.final_regs[t] = final_state;

        std::vector<MemoryAccess> trial_mem;
        trial_mem.reserve(sim.mem_accesses.size());
        for (const auto& m : sim.mem_accesses) {
            trial_mem.push_back({ m.is_write, m.addr, m.value, m.reg_src });
        }
        data.memory_accesses[t] = std::move(trial_mem);
    }
    return data;
}

/**
 * @brief Checks if all trials have the same number of memory accesses.
 */
inline bool is_access_count_consistent(const SimulationData& data) {
    size_t num_accesses = data.memory_accesses[0].size();
    for (size_t t = 1; t < data.initial_regs.size(); ++t)
        if (data.memory_accesses[t].size() != num_accesses) return false;
    return true;
}

/**
 * @brief Returns memory name if consistent across all trials, otherwise "mem[unknown]".
 */
inline std::string get_consistent_memory_name(const SimulationData& data, size_t idx) {
    std::string mem_name = get_memory_name(data.memory_accesses[0][idx].address, data.initial_regs[0]);
    for (size_t t = 1; t < data.initial_regs.size(); ++t)
        if (get_memory_name(data.memory_accesses[t][idx].address, data.initial_regs[t]) != mem_name)
            return "mem[unknown]";
    return mem_name;
}

/**
 * @brief Checks if a value computed for each trial is stable (same across all trials).
 */
template<typename T, typename Func>
bool is_stable_value(size_t trials, Func compute, T& stable_value) {
    stable_value = compute(0);
    for (size_t t = 1; t < trials; ++t)
        if (compute(t) != stable_value) return false;
    return true;
}

/**
 * @brief Checks if a predicate is true for all trials.
 */
template<typename Pred>
bool all_trials_match(size_t trials, Pred pred) {
    for (size_t t = 0; t < trials; ++t)
        if (!pred(t)) return false;
    return true;
}

/**
 * @brief Finds registers that ended up with a constant non-zero value.
 * Example: rax = 0x42 (always)
 */
inline std::vector<Relation> find_register_constants(const SimulationData& data) {
    std::vector<Relation> relations;
    size_t trials = data.initial_regs.size();

    for (int reg_id : Simulator::TRACKED_REGS) {
        if (data.final_regs[0].find(reg_id) == data.final_regs[0].end()) continue;
        uint64_t constant;
        auto compute = [&](size_t t) {
            auto it = data.final_regs[t].find(reg_id);
            return (it != data.final_regs[t].end()) ? it->second : 0;
            };
        if (is_stable_value(trials, compute, constant) && constant != 0) {
            relations.push_back({ Simulator::reg_name(reg_id), "0x0", static_cast<int64_t>(constant), true });
        }
    }
    return relations;
}

/**
 * @brief Finds registers whose delta (final - initial) is constant across all trials.
 * Example: rax_final - rax_initial = 8
 */
inline std::vector<Relation> find_register_deltas(const SimulationData& data) {
    std::vector<Relation> relations;
    size_t trials = data.initial_regs.size();

    for (int reg_id : Simulator::TRACKED_REGS) {
        if (data.final_regs[0].find(reg_id) == data.final_regs[0].end() ||
            data.initial_regs[0].find(reg_id) == data.initial_regs[0].end()) continue;

        int64_t delta;
        auto compute = [&](size_t t) {
            auto fin_it = data.final_regs[t].find(reg_id);
            auto init_it = data.initial_regs[t].find(reg_id);
            if (fin_it == data.final_regs[t].end() || init_it == data.initial_regs[t].end()) return int64_t(0);
            return static_cast<int64_t>(fin_it->second) - static_cast<int64_t>(init_it->second);
            };

        if (is_stable_value(trials, compute, delta) && delta != 0) {
            std::string name = Simulator::reg_name(reg_id);
            relations.push_back({ name, name, delta, true });
        }
    }
    return relations;
}

/**
 * @brief Finds constant deltas between pairs of registers across all trials.
 * Example: rax - rbx = 0x10
 */
inline std::vector<Relation> find_register_pair_deltas(const SimulationData& data) {
    std::vector<Relation> relations;
    size_t trials = data.initial_regs.size();

    for (int r1 : Simulator::TRACKED_REGS) {
        if (data.final_regs[0].find(r1) == data.final_regs[0].end()) continue;
        for (int r2 : Simulator::TRACKED_REGS) {
            if (r1 == r2 || data.final_regs[0].find(r2) == data.final_regs[0].end()) continue;

            int64_t delta;
            auto compute = [&](size_t t) {
                auto it1 = data.final_regs[t].find(r1);
                auto it2 = data.final_regs[t].find(r2);
                if (it1 == data.final_regs[t].end() || it2 == data.final_regs[t].end()) return int64_t(0);
                return static_cast<int64_t>(it1->second) - static_cast<int64_t>(it2->second);
                };

            if (is_stable_value(trials, compute, delta)) {
                relations.push_back({ Simulator::reg_name(r1), Simulator::reg_name(r2), delta, true });
            }
        }
    }
    return relations;
}

/**
 * @brief Finds stable relationships between memory and registers.
 * Example: mem[rax] = rbx + 0x8
 */
inline std::vector<Relation> find_memory_register_relations(const SimulationData& data) {
    std::vector<Relation> relations;
    size_t trials = data.initial_regs.size();
    size_t num_accesses = data.memory_accesses[0].size();

    for (size_t idx = 0; idx < num_accesses; ++idx) {
        bool is_write_type = data.memory_accesses[0][idx].is_write;
        bool consistent_type = true;

        for (size_t t = 1; t < trials; ++t)
            if (data.memory_accesses[t][idx].is_write != is_write_type) { consistent_type = false; break; }
        if (!consistent_type) continue;

        for (int reg_id : Simulator::TRACKED_REGS) {
            if (data.final_regs[0].find(reg_id) == data.final_regs[0].end()) continue;

            int64_t delta;
            auto compute = [&](size_t t) {
                auto reg_it = data.final_regs[t].find(reg_id);
                return static_cast<int64_t>(data.memory_accesses[t][idx].value) -
                    (reg_it != data.final_regs[t].end() ? static_cast<int64_t>(reg_it->second) : 0);
                };

            if (is_stable_value(trials, compute, delta)) {
                std::string mem_name = get_consistent_memory_name(data, idx);
                std::string reg_name = Simulator::reg_name(reg_id);
                relations.push_back(is_write_type ? Relation{ mem_name, reg_name, delta, true }
                : Relation{ reg_name, mem_name, -delta, true });
            }
        }
    }
    return relations;
}

/**
 * @brief Finds constant differences between memory pairs.
 * Example: mem[0x1000] - mem[0x2000] = 0x8
 */
inline std::vector<Relation> find_memory_pair_deltas(const SimulationData& data) {
    std::vector<Relation> relations;
    size_t trials = data.initial_regs.size();
    size_t num_accesses = data.memory_accesses[0].size();

    for (size_t i = 0; i < num_accesses; ++i) {
        for (size_t j = i + 1; j < num_accesses; ++j) {
            bool type_i = data.memory_accesses[0][i].is_write;
            bool type_j = data.memory_accesses[0][j].is_write;
            bool stable = true;

            for (size_t t = 1; t < trials; ++t) {
                if (data.memory_accesses[t][i].is_write != type_i || data.memory_accesses[t][j].is_write != type_j) {
                    stable = false; break;
                }
            }
            if (!stable) continue;

            int64_t delta;
            auto compute = [&](size_t t) {
                return static_cast<int64_t>(data.memory_accesses[t][i].value) -
                    static_cast<int64_t>(data.memory_accesses[t][j].value);
                };

            if (is_stable_value(trials, compute, delta)) {
                relations.push_back({ get_consistent_memory_name(data, i),
                                      get_consistent_memory_name(data, j), delta, true });
            }
        }
    }
    return relations;
}

/**
 * @brief Finds register operations related to memory reads (mov/add/sub).
 * Example: rax = mem[rbx], rax = init_rax + mem[rcx]
 */
inline std::vector<Relation> find_register_memory_operations(const SimulationData& data) {
    std::vector<Relation> relations;
    size_t trials = data.initial_regs.size();
    size_t num_accesses = data.memory_accesses[0].size();

    for (int reg_id : Simulator::TRACKED_REGS) {
        if (data.final_regs[0].find(reg_id) == data.final_regs[0].end() ||
            data.initial_regs[0].find(reg_id) == data.initial_regs[0].end()) continue;

        for (size_t idx = 0; idx < num_accesses; ++idx) {
            if (data.memory_accesses[0][idx].is_write) continue;
            std::string reg_name = Simulator::reg_name(reg_id);
            std::string mem_name = get_consistent_memory_name(data, idx);

            auto mov_pred = [&](size_t t) {
                auto it = data.final_regs[t].find(reg_id);
                return it != data.final_regs[t].end() && it->second == data.memory_accesses[t][idx].value;
                };
            if (all_trials_match(trials, mov_pred)) { relations.push_back({ reg_name, mem_name, 0, true }); continue; }

            auto add_pred = [&](size_t t) {
                auto fin_it = data.final_regs[t].find(reg_id);
                auto init_it = data.initial_regs[t].find(reg_id);
                return fin_it != data.final_regs[t].end() && init_it != data.initial_regs[t].end() &&
                    fin_it->second == init_it->second + data.memory_accesses[t][idx].value;
                };
            if (all_trials_match(trials, add_pred)) { relations.push_back({ reg_name, "init_" + reg_name + " + " + mem_name, 0, true }); continue; }

            auto sub_pred = [&](size_t t) {
                auto fin_it = data.final_regs[t].find(reg_id);
                auto init_it = data.initial_regs[t].find(reg_id);
                return fin_it != data.final_regs[t].end() && init_it != data.initial_regs[t].end() &&
                    fin_it->second == init_it->second - data.memory_accesses[t][idx].value;
                };
            if (all_trials_match(trials, sub_pred)) { relations.push_back({ reg_name, "init_" + reg_name + " - " + mem_name, 0, true }); }
        }
    }
    return relations;
}

/**
 * @brief Aggregates all constant relations found in a code snippet via simulation.
 */
inline std::vector<Relation> find_constant_relations(Simulator& sim, const std::vector<uint8_t>& code, int trials = 5) {
    auto data = run_simulations(sim, code, trials);
    if (!is_access_count_consistent(data)) return {};

    std::vector<Relation> relations;
    auto append = [&](const std::vector<Relation>& r) { relations.insert(relations.end(), r.begin(), r.end()); };

    append(find_register_constants(data));
    append(find_register_deltas(data));
    append(find_register_pair_deltas(data));
    append(find_memory_register_relations(data));
    append(find_memory_pair_deltas(data));
    append(find_register_memory_operations(data));

    return relations;
}

/**
 * @brief Analyzes a single execution for register changes, memory accesses, and constant relations.
 */
inline ExecutionResult analyze_execution(Simulator& sim, const std::vector<uint8_t>& code, const RegMap& initial_regs, const RegMap& final_regs) {
    ExecutionResult result;

    for (auto& reg : final_regs) {
        auto it = initial_regs.find(reg.first);
        uint64_t old_val = (it != initial_regs.end()) ? it->second : 0;
        if (it == initial_regs.end() || old_val != reg.second)
            result.reg_changes.push_back({ sim.reg_name(reg.first), old_val, reg.second });
    }

    for (auto& m : sim.mem_accesses)
        result.mem_accesses.push_back({ m.is_write, m.addr, m.value, m.reg_src });

    result.relations = find_constant_relations(sim, code, 5);
    return result;
}

/**
 * @brief Prints register changes in a human-readable format.
 */
inline void print_register_changes(const ExecutionResult& result) {
    std::cout << "--- Registers Changed ---\n";
    for (auto& rc : result.reg_changes)
        std::cout << rc.name << ": 0x" << std::hex << rc.old_value << " -> 0x" << rc.new_value << "\n";
}

/**
 * @brief Prints memory accesses in a human-readable format.
 */
inline void print_memory_accesses(const ExecutionResult& result) {
    std::cout << "--- Memory Accesses ---\n";
    for (auto& ma : result.mem_accesses) {
        std::cout << (ma.is_write ? "[WRITE] " : "[READ] ") << "0x" << std::hex << ma.address
            << " val=0x" << ma.value;
        if (ma.source_reg != -1) std::cout << " (from reg: " << Simulator::reg_name(ma.source_reg) << ")";
        std::cout << "\n";
    }
}

/**
 * @brief Prints constant relations found during execution analysis.
 */
inline void print_relations(const ExecutionResult& result) {
    std::cout << "--- Constant Relations ---\n";
    for (auto& r : result.relations) {
        if (!r.valid) continue;
        std::cout << r.lhs << " = " << r.rhs;
        if (r.delta > 0) std::cout << " + 0x" << std::hex << r.delta;
        else if (r.delta < 0) std::cout << " - 0x" << std::hex << -r.delta;
        std::cout << std::dec << "\n";
    }
}
