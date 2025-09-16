#pragma once
#include "simulator.h"
#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <functional>
#include <algorithm>

// ---------------- Data Structures ----------------
struct RegisterChange {
    std::string name;
    uint64_t old_value;
    uint64_t new_value;
};

struct MemoryAccess {
    bool is_write;
    uint64_t address;
    uint64_t value;
    int source_reg; // register id that generated the access, -1 if unknown
};

struct Relation {
    std::string lhs;
    std::string rhs;
    int64_t delta;
    bool valid = true;

    bool operator==(const Relation& other) const {
        return lhs == other.lhs && rhs == other.rhs && delta == other.delta && valid == other.valid;
    }
};

struct ExecutionResult {
    std::vector<RegisterChange> reg_changes;
    std::vector<MemoryAccess> mem_accesses;
    std::vector<Relation> relations;
};

struct SimulationData {
    std::vector<RegMap> initial_regs;
    std::vector<RegMap> final_regs;
    std::vector<std::vector<MemoryAccess>> memory_accesses;
};

// ---------------- Utilities ----------------
inline std::string to_hex(uint64_t value) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%llX", value);
    return buf;
}

inline std::string get_memory_name(uint64_t addr, const RegMap& regs) {
    for (int reg_id : Simulator::TRACKED_REGS) {
        auto it = regs.find(reg_id);
        if (it == regs.end()) continue;
        int64_t offset = static_cast<int64_t>(addr) - static_cast<int64_t>(it->second);
        if (std::abs(offset) < 0x1000) {
            std::string reg_name = Simulator::reg_name(reg_id);
            if (offset == 0) return "mem[" + reg_name + "]";
            std::string sign = offset > 0 ? " + 0x" : " - 0x";
            return "mem[" + reg_name + sign + to_hex(std::abs(offset)) + "]";
        }
    }
    return "mem[0x" + to_hex(addr) + "]";
}

// ---------------- Simulation ----------------
inline SimulationData run_simulations(Simulator& sim, const std::vector<uint8_t>& code, int trials = 5) {
    SimulationData data;
    data.initial_regs.reserve(trials);
    data.final_regs.reserve(trials);
    data.memory_accesses.reserve(trials);

    for (int t = 0; t < trials; ++t) {
        RegMap initial = Simulator::make_random_regs();
        data.initial_regs.push_back(initial);
        RegMap final_state;
        sim.emulate(code, initial, final_state);
        data.final_regs.push_back(final_state);

        std::vector<MemoryAccess> trial_mem;
        for (const auto& m : sim.mem_accesses)
            trial_mem.push_back({ m.is_write, m.addr, m.value, m.reg_src });
        data.memory_accesses.push_back(std::move(trial_mem));
    }
    return data;
}

inline bool is_access_count_consistent(const SimulationData& data) {
    if (data.memory_accesses.empty()) return true;
    size_t n = data.memory_accesses[0].size();
    return std::all_of(data.memory_accesses.begin() + 1, data.memory_accesses.end(),
        [n](const auto& acc) { return acc.size() == n; });
}

inline std::string get_consistent_memory_name(const SimulationData& data, size_t idx) {
    std::string mem_name = get_memory_name(data.memory_accesses[0][idx].address, data.initial_regs[0]);
    for (size_t t = 1; t < data.initial_regs.size(); ++t)
        if (get_memory_name(data.memory_accesses[t][idx].address, data.initial_regs[t]) != mem_name)
            return "mem[unknown]";
    return mem_name;
}

// ---------------- Generic helpers ----------------
template<typename T, typename Func>
bool is_stable_value(size_t trials, Func compute, T& stable_value) {
    if (trials == 0) return false;
    stable_value = compute(0);
    for (size_t t = 1; t < trials; ++t)
        if (compute(t) != stable_value) return false;
    return true;
}

template<typename Pred>
bool all_trials_match(size_t trials, Pred pred) {
    for (size_t t = 0; t < trials; ++t)
        if (!pred(t)) return false;
    return true;
}

// ---------- Generic relation finder ----------
template<typename IterPolicy, typename ComputePolicy, typename RelationPolicy>
std::vector<Relation> find_relations_generic(
    size_t trials,
    IterPolicy iter,
    ComputePolicy compute,
    RelationPolicy make_relation)
{
    std::vector<Relation> relations;
    for (auto [lhs, rhs] : iter()) {
        int64_t delta;
        auto fn = [&](size_t t) { return compute(t, lhs, rhs); };
        if (is_stable_value(trials, fn, delta)) {
            // skip meaningless ones like RBX = RBX with delta=0
            if (delta == 0 && lhs == rhs) continue;
            relations.push_back(make_relation(lhs, rhs, delta));
        }
    }
    // remove duplicates
    auto end_it = std::unique(relations.begin(), relations.end());
    relations.erase(end_it, relations.end());
    return relations;
}

// ---------------- Register Relations ----------------
inline std::vector<Relation> find_register_relations(const SimulationData& data) {
    size_t trials = data.initial_regs.size();
    std::vector<Relation> out;

    // Constant registers
    for (int reg_id : Simulator::TRACKED_REGS) {
        uint64_t constant;
        auto compute = [&](size_t t) {
            auto it = data.final_regs[t].find(reg_id);
            return it == data.final_regs[t].end() ? 0ull : it->second;
            };
        if (is_stable_value(trials, compute, constant) && constant != 0) {
            out.push_back({ Simulator::reg_name(reg_id), "0x0",
                            static_cast<int64_t>(constant), true });
        }
    }

    // Delta with self
    auto self_deltas = find_relations_generic(
        trials,
        []() {
            std::vector<std::pair<int, int>> v;
            for (int r : Simulator::TRACKED_REGS) v.push_back({ r,r });
            return v;
        },
        [&](size_t t, int r1, int r2) {
            auto fin = data.final_regs[t].at(r1);
            auto init = data.initial_regs[t].at(r2);
            return static_cast<int64_t>(fin) - static_cast<int64_t>(init);
        },
        [&](int r1, int r2, int64_t d) {
            std::string name = Simulator::reg_name(r1);
            return Relation{ name, name, d, true };
        }
    );
    out.insert(out.end(), self_deltas.begin(), self_deltas.end());

    // Pair deltas
    auto pair_deltas = find_relations_generic(
        trials,
        []() {
            std::vector<std::pair<int, int>> v;
            for (int r1 : Simulator::TRACKED_REGS)
                for (int r2 : Simulator::TRACKED_REGS)
                    if (r1 != r2) v.push_back({ r1,r2 });
            return v;
        },
        [&](size_t t, int r1, int r2) {
            auto fin = data.final_regs[t].at(r1);
            auto init = data.initial_regs[t].at(r2);
            return static_cast<int64_t>(fin) - static_cast<int64_t>(init);
        },
        [&](int r1, int r2, int64_t d) {
            return Relation{ Simulator::reg_name(r1), Simulator::reg_name(r2), d, true };
        }
    );
    out.insert(out.end(), pair_deltas.begin(), pair_deltas.end());

    return out;
}

// ---------------- Memory Relations ----------------
inline std::vector<Relation> find_memory_relations(const SimulationData& data) {
    size_t trials = data.initial_regs.size();
    size_t num_accesses = data.memory_accesses.empty() ? 0 : data.memory_accesses[0].size();
    std::vector<Relation> out;

    // Memory-register relations
    for (size_t idx = 0; idx < num_accesses; ++idx) {
        bool is_write = data.memory_accesses[0][idx].is_write;
        if (!std::all_of(data.memory_accesses.begin() + 1, data.memory_accesses.end(),
            [idx, is_write](const auto& acc) { return acc[idx].is_write == is_write; })) continue;

        std::string mem_name = get_consistent_memory_name(data, idx);

        auto rels = find_relations_generic(
            trials,
            [&]() {
                std::vector<std::pair<int, int>> v;
                for (int r : Simulator::TRACKED_REGS) v.push_back({ (int)idx,r });
                return v;
            },
            [&](size_t t, int i, int r) {
                auto reg = data.final_regs[t].at(r);
                return static_cast<int64_t>(data.memory_accesses[t][i].value) -
                    static_cast<int64_t>(reg);
            },
            [&](int i, int r, int64_t d) {
                std::string reg_name = Simulator::reg_name(r);
                return is_write ? Relation{ mem_name, reg_name, d, true }
                : Relation{ reg_name, mem_name, -d, true };
            }
        );
        out.insert(out.end(), rels.begin(), rels.end());
    }

    // Memory pair deltas
    auto mem_pairs = find_relations_generic(
        trials,
        [&]() {
            std::vector<std::pair<int, int>> v;
            for (size_t i = 0; i < num_accesses; ++i)
                for (size_t j = i + 1; j < num_accesses; ++j)
                    v.push_back({ (int)i,(int)j });
            return v;
        },
        [&](size_t t, int i, int j) {
            return static_cast<int64_t>(data.memory_accesses[t][i].value) -
                static_cast<int64_t>(data.memory_accesses[t][j].value);
        },
        [&](int i, int j, int64_t d) {
            return Relation{ get_consistent_memory_name(data,i),
                            get_consistent_memory_name(data,j), d, true };
        }
    );
    out.insert(out.end(), mem_pairs.begin(), mem_pairs.end());

    return out;
}

// ---------------- Register-Memory Ops ----------------
inline std::vector<Relation> find_register_memory_operations(const SimulationData& data) {
    std::vector<Relation> out;
    size_t trials = data.initial_regs.size();
    size_t num_accesses = data.memory_accesses.empty() ? 0 : data.memory_accesses[0].size();

    for (int reg_id : Simulator::TRACKED_REGS) {
        std::string reg_name = Simulator::reg_name(reg_id);

        for (size_t idx = 0; idx < num_accesses; ++idx) {
            if (data.memory_accesses[0][idx].is_write) continue;
            std::string mem_name = get_consistent_memory_name(data, idx);

            auto mov_pred = [&](size_t t) {
                return data.final_regs[t].at(reg_id) == data.memory_accesses[t][idx].value;
                };
            if (all_trials_match(trials, mov_pred)) {
                out.push_back({ reg_name, mem_name, 0, true });
                continue;
            }

            auto add_pred = [&](size_t t) {
                return data.final_regs[t].at(reg_id) ==
                    (data.initial_regs[t].at(reg_id) + data.memory_accesses[t][idx].value);
                };
            if (all_trials_match(trials, add_pred)) {
                out.push_back({ reg_name, "init_" + reg_name + " + " + mem_name, 0, true });
                continue;
            }

            auto sub_pred = [&](size_t t) {
                return data.final_regs[t].at(reg_id) ==
                    (data.initial_regs[t].at(reg_id) - data.memory_accesses[t][idx].value);
                };
            if (all_trials_match(trials, sub_pred)) {
                out.push_back({ reg_name, "init_" + reg_name + " - " + mem_name, 0, true });
            }
        }
    }
    // remove duplicates
    auto end_it = std::unique(out.begin(), out.end());
    out.erase(end_it, out.end());
    return out;
}

// ---------------- Aggregation ----------------
inline std::vector<Relation> find_constant_relations(Simulator& sim,
    const std::vector<uint8_t>& code, int trials = 5)
{
    auto data = run_simulations(sim, code, trials);
    if (!is_access_count_consistent(data)) return {};

    std::vector<Relation> relations;
    auto append = [&](const auto& r) {
        relations.insert(relations.end(), r.begin(), r.end());
        };

    append(find_register_relations(data));
    append(find_memory_relations(data));
    append(find_register_memory_operations(data));

    auto end_it = std::unique(relations.begin(), relations.end());
    relations.erase(end_it, relations.end());
    return relations;
}

// ---------------- Execution Analysis ----------------
inline ExecutionResult analyze_execution(Simulator& sim,
    const std::vector<uint8_t>& code,
    const RegMap& initial_regs,
    const RegMap& final_regs)
{
    ExecutionResult result;

    for (const auto& [reg_id, new_val] : final_regs) {
        uint64_t old_val = initial_regs.at(reg_id);
        if (new_val != old_val)
            result.reg_changes.push_back({ Simulator::reg_name(reg_id), old_val, new_val });
    }

    for (const auto& m : sim.mem_accesses)
        result.mem_accesses.push_back({ m.is_write, m.addr, m.value, m.reg_src });

    result.relations = find_constant_relations(sim, code, 5);
    return result;
}

// ---------------- Printers ----------------
inline void print_execution_result(const ExecutionResult& result) {
    std::cout << "--- Registers Changed ---\n";
    for (const auto& rc : result.reg_changes)
        std::cout << rc.name << ": 0x" << std::hex << rc.old_value
        << " -> 0x" << rc.new_value << "\n";

    std::cout << "--- Memory Accesses ---\n";
    for (const auto& ma : result.mem_accesses) {
        std::cout << (ma.is_write ? "[WRITE] " : "[READ] ")
            << "0x" << std::hex << ma.address
            << " val=0x" << ma.value;
        if (ma.source_reg != -1)
            std::cout << " (from reg: " << Simulator::reg_name(ma.source_reg) << ")";
        std::cout << "\n";
    }

    std::cout << "--- Constant Relations ---\n";
    for (const auto& r : result.relations) {
        if (!r.valid) continue;
        std::cout << r.lhs << " = " << r.rhs;
        if (r.delta > 0) std::cout << " + 0x" << std::hex << r.delta;
        else if (r.delta < 0) std::cout << " - 0x" << std::hex << -r.delta;
        std::cout << std::dec << "\n";
    }
}
