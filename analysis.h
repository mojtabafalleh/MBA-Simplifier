#pragma once
#include "simulator.h"
#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <functional>
#include <algorithm>
#include <unordered_set>

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
    int source_reg;
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
            relations.push_back(make_relation(lhs, rhs, delta));
        }
    }
    auto end_it = std::unique(relations.begin(), relations.end());
    relations.erase(end_it, relations.end());
    return relations;
}

// ---------------- Subregister specs ----------------
struct SubRegSpec {
    int base_reg;
    std::string name;
    uint64_t mask;
};

inline std::vector<SubRegSpec> get_subregs_for(int reg_id) {
    const uint64_t M32 = 0xFFFFFFFFULL;
    const uint64_t M16 = 0xFFFFULL;
    const uint64_t M8 = 0xFFULL;

    switch (reg_id) {
    case UC_X86_REG_RAX:
        return { {reg_id, "EAX", M32}, {reg_id, "AX", M16}, {reg_id, "AL", M8} };
    case UC_X86_REG_RBX:
        return { {reg_id, "EBX", M32}, {reg_id, "BX", M16}, {reg_id, "BL", M8} };
    case UC_X86_REG_RCX:
        return { {reg_id, "ECX", M32}, {reg_id, "CX", M16}, {reg_id, "CL", M8} };
    case UC_X86_REG_RDX:
        return { {reg_id, "EDX", M32}, {reg_id, "DX", M16}, {reg_id, "DL", M8} };
    case UC_X86_REG_RSI:
        return { {reg_id, "ESI", M32}, {reg_id, "SI", M16}, {reg_id, "SIL", M8} };
    case UC_X86_REG_RDI:
        return { {reg_id, "EDI", M32}, {reg_id, "DI", M16}, {reg_id, "DIL", M8} };
    case UC_X86_REG_RSP:
        return { {reg_id, "ESP", M32}, {reg_id, "SP", M16}, {reg_id, "SPL", M8} };
    case UC_X86_REG_RBP:
        return { {reg_id, "EBP", M32}, {reg_id, "BP", M16}, {reg_id, "BPL", M8} };
    case UC_X86_REG_R8:
        return { {reg_id, "R8D", M32},  {reg_id, "R8W", M16},  {reg_id, "R8B", M8} };
    case UC_X86_REG_R9:
        return { {reg_id, "R9D", M32},  {reg_id, "R9W", M16},  {reg_id, "R9B", M8} };
    case UC_X86_REG_R10:
        return { {reg_id, "R10D", M32}, {reg_id, "R10W", M16}, {reg_id, "R10B", M8} };
    case UC_X86_REG_R11:
        return { {reg_id, "R11D", M32}, {reg_id, "R11W", M16}, {reg_id, "R11B", M8} };
    case UC_X86_REG_R12:
        return { {reg_id, "R12D", M32}, {reg_id, "R12W", M16}, {reg_id, "R12B", M8} };
    case UC_X86_REG_R13:
        return { {reg_id, "R13D", M32}, {reg_id, "R13W", M16}, {reg_id, "R13B", M8} };
    case UC_X86_REG_R14:
        return { {reg_id, "R14D", M32}, {reg_id, "R14W", M16}, {reg_id, "R14B", M8} };
    case UC_X86_REG_R15:
        return { {reg_id, "R15D", M32}, {reg_id, "R15W", M16}, {reg_id, "R15B", M8} };
    default:
        return {};
    }
}

inline uint64_t extract_masked(const RegMap& regs, int base_reg, uint64_t mask) {
    auto it = regs.find(base_reg);
    if (it == regs.end()) return 0;
    return it->second & mask;
}

// Helper to compute changed base registers
inline std::unordered_set<int> compute_changed_bases(const SimulationData& data) {
    size_t trials = data.initial_regs.size();
    std::unordered_set<int> changed_regs;
    for (size_t t = 0; t < trials; ++t) {
        for (const auto& kv : data.initial_regs[t]) {
            int rid = kv.first;
            auto fit = data.final_regs[t].find(rid);
            uint64_t fv = (fit != data.final_regs[t].end()) ? fit->second : 0ULL;
            if (fv != kv.second) {
                changed_regs.insert(rid);
            }
        }
    }
    return changed_regs;
}

// ---------------- Register Relations ----------------
inline std::vector<Relation> find_register_relations(const SimulationData& data, bool allow_subregs = true) {
    size_t trials = data.initial_regs.size();
    std::unordered_set<int> changed_regs = compute_changed_bases(data);
    std::vector<Relation> out;

    // ---------------- 1) constants for 64-bit regs ----------------
    for (int reg_id : changed_regs) {
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

    // ---------------- 2) self-deltas for 64-bit regs ----------------
    auto self_deltas = find_relations_generic(
        trials,
        [&]() {
            std::vector<std::pair<int, int>> v;
            for (int r : changed_regs) v.push_back({ r, r });
            return v;
        },
        [&](size_t t, int r1, int r2) {
            auto fin = data.final_regs[t].at(r1);
            auto init = data.initial_regs[t].at(r2);
            return static_cast<int64_t>(fin) - static_cast<int64_t>(init);
        },
        [&](int r1, int r2, int64_t d) {
            if (d == 0) return Relation{ "", "", 0, false }; // Invalid to skip
            std::string name = Simulator::reg_name(r1);
            return Relation{ name, "init_" + name, d, true };
        }
    );
    out.insert(out.end(), self_deltas.begin(), self_deltas.end());

    // ---------------- 3) pair deltas for 64-bit regs ----------------
    auto pair_deltas = find_relations_generic(
        trials,
        [&]() {
            std::vector<std::pair<int, int>> v;
            for (int r1 : changed_regs)
                for (int r2 : Simulator::TRACKED_REGS)
                    if (r1 != r2) v.push_back({ r1, r2 });
            return v;
        },
        [&](size_t t, int r1, int r2) {
            auto fin = data.final_regs[t].find(r1);
            auto init = data.initial_regs[t].find(r2);
            uint64_t fin_val = (fin != data.final_regs[t].end()) ? fin->second : 0;
            uint64_t init_val = (init != data.initial_regs[t].end()) ? init->second : 0;
            return static_cast<int64_t>(fin_val) - static_cast<int64_t>(init_val);
        },
        [&](int r1, int r2, int64_t d) {
            return Relation{ Simulator::reg_name(r1), "init_" + Simulator::reg_name(r2), d, true };
        }
    );
    out.insert(out.end(), pair_deltas.begin(), pair_deltas.end());

    // If subregister analysis is disabled, return now.
    if (!allow_subregs) {
        return out;
    }

    // ---------------- Subregister analysis ----------------
    struct VReg { int base_reg; std::string name; uint64_t mask; };
    std::vector<VReg> vregs;
    for (int r : Simulator::TRACKED_REGS) {
        auto subs = get_subregs_for(r);
        for (auto& s : subs) vregs.push_back({ s.base_reg, s.name, s.mask });
    }

    if (vregs.empty()) return out;

    size_t N = vregs.size();

    // Compute changed subregs (only for subs of changed bases)
    std::vector<size_t> changed_sub_indices;
    for (size_t i = 0; i < N; ++i) {
        if (changed_regs.count(vregs[i].base_reg) == 0) continue;
        int64_t sub_delta;
        auto fn_sub = [&](size_t t) {
            uint64_t ff = extract_masked(data.final_regs[t], vregs[i].base_reg, vregs[i].mask);
            uint64_t ii = extract_masked(data.initial_regs[t], vregs[i].base_reg, vregs[i].mask);
            return static_cast<int64_t>(ff - ii);
            };
        if (!is_stable_value(trials, fn_sub, sub_delta) || sub_delta != 0) {
            changed_sub_indices.push_back(i);
        }
    }

    if (changed_sub_indices.empty()) return out;

    // constants for subregs
    for (size_t ci : changed_sub_indices) {
        size_t i = ci;
        uint64_t constant;
        auto compute = [&](size_t t) {
            return extract_masked(data.final_regs[t], vregs[i].base_reg, vregs[i].mask);
            };
        if (is_stable_value(trials, compute, constant) && constant != 0) {
            out.push_back({ vregs[i].name, "0x0", static_cast<int64_t>(constant), true });
        }
    }

    // self deltas for subregs: final(sub_i) - init(sub_i)
    for (size_t ci : changed_sub_indices) {
        size_t i = ci;
        int64_t delta;
        auto fn = [&](size_t t) {
            uint64_t fin = extract_masked(data.final_regs[t], vregs[i].base_reg, vregs[i].mask);
            uint64_t init = extract_masked(data.initial_regs[t], vregs[i].base_reg, vregs[i].mask);
            return static_cast<int64_t>(fin) - static_cast<int64_t>(init);
            };
        if (is_stable_value(trials, fn, delta)) {
            if (delta == 0) continue;
            out.push_back({ vregs[i].name, "init_" + vregs[i].name, delta, true });
        }
    }

    // pair deltas across subregs: final(sub_i) - init(sub_j)
    for (size_t ci : changed_sub_indices) {
        size_t i = ci;
        for (size_t j = 0; j < N; ++j) {
            if (i == j) continue;
            int64_t delta;
            auto fn = [&](size_t t) {
                uint64_t fin = extract_masked(data.final_regs[t], vregs[i].base_reg, vregs[i].mask);
                uint64_t init = extract_masked(data.initial_regs[t], vregs[j].base_reg, vregs[j].mask);
                return static_cast<int64_t>(fin) - static_cast<int64_t>(init);
                };
            if (is_stable_value(trials, fn, delta)) {
                // Removed: if (delta == 0) continue; to allow mov detection
                out.push_back({ vregs[i].name, "init_" + vregs[j].name, delta, true });
            }
        }
    }

    return out;
}

// ---------------- Register-Register Operations (Add/Sub/Mul) ----------------
inline std::vector<Relation> find_register_register_operations(const SimulationData& data, bool allow_subregs = true) {
    std::vector<Relation> out;
    size_t trials = data.initial_regs.size();
    std::unordered_set<int> changed_regs = compute_changed_bases(data);

    // Generic for add/sub between regs
    auto arith_generic = [&](std::function<uint64_t(uint64_t, uint64_t)> op, const std::string& op_name) {
        for (int r1 : changed_regs) {
            for (int r2 : Simulator::TRACKED_REGS) {
                if (r1 == r2) continue;
                auto pred = [&](size_t t) {
                    uint64_t f = data.final_regs[t].at(r1);
                    uint64_t i1 = data.initial_regs[t].at(r1);
                    uint64_t i2 = data.initial_regs[t].at(r2);
                    return f == op(i1, i2);
                    };
                if (all_trials_match(trials, pred)) {
                    std::string lhs = Simulator::reg_name(r1);
                    std::string rhs = "init_" + Simulator::reg_name(r1) + " " + op_name + " init_" + Simulator::reg_name(r2);
                    out.push_back({ lhs, rhs, 0, true });
                }
            }
        }
        };

    arith_generic([](uint64_t a, uint64_t b) { return a + b; }, "+");
    arith_generic([](uint64_t a, uint64_t b) { return a - b; }, "-");
    // Add mul if needed: arith_generic([](uint64_t a, uint64_t b) { return a * b; }, "*");

    if (!allow_subregs) return out;

    // Subregs version (similar logic with extract_masked)
    struct VReg { int base_reg; std::string name; uint64_t mask; };
    std::vector<VReg> vregs;
    for (int r : Simulator::TRACKED_REGS) {
        auto subs = get_subregs_for(r);
        for (auto& s : subs) vregs.push_back({ s.base_reg, s.name, s.mask });
    }
    size_t N = vregs.size();

    // Compute changed subregs (only for subs of changed bases)
    std::vector<size_t> changed_sub_indices;
    for (size_t i = 0; i < N; ++i) {
        if (changed_regs.count(vregs[i].base_reg) == 0) continue;
        int64_t sub_delta;
        auto fn_sub = [&](size_t t) {
            uint64_t ff = extract_masked(data.final_regs[t], vregs[i].base_reg, vregs[i].mask);
            uint64_t ii = extract_masked(data.initial_regs[t], vregs[i].base_reg, vregs[i].mask);
            return static_cast<int64_t>(ff - ii);
            };
        if (!is_stable_value(trials, fn_sub, sub_delta) || sub_delta != 0) {
            changed_sub_indices.push_back(i);
        }
    }

    if (changed_sub_indices.empty()) return out;

    for (size_t ci : changed_sub_indices) {
        size_t i = ci;
        for (size_t j = 0; j < N; ++j) {
            if (i == j) continue;
            auto pred_add = [&](size_t t) {
                uint64_t f = extract_masked(data.final_regs[t], vregs[i].base_reg, vregs[i].mask);
                uint64_t i1 = extract_masked(data.initial_regs[t], vregs[i].base_reg, vregs[i].mask);
                uint64_t i2 = extract_masked(data.initial_regs[t], vregs[j].base_reg, vregs[j].mask);
                return f == (i1 + i2) && f <= vregs[i].mask;  // Overflow check approximate
                };
            if (all_trials_match(trials, pred_add)) {
                out.push_back({ vregs[i].name, "init_" + vregs[i].name + " + init_" + vregs[j].name, 0, true });
            }
            // Similar for sub
            auto pred_sub = [&](size_t t) {
                uint64_t f = extract_masked(data.final_regs[t], vregs[i].base_reg, vregs[i].mask);
                uint64_t i1 = extract_masked(data.initial_regs[t], vregs[i].base_reg, vregs[i].mask);
                uint64_t i2 = extract_masked(data.initial_regs[t], vregs[j].base_reg, vregs[j].mask);
                return f == (i1 - i2) && f <= vregs[i].mask;
                };
            if (all_trials_match(trials, pred_sub)) {
                out.push_back({ vregs[i].name, "init_" + vregs[i].name + " - init_" + vregs[j].name, 0, true });
            }
        }
    }

    return out;
}

// ---------------- Bitwise Operations ----------------

inline std::vector<Relation> find_bitwise_operations(const SimulationData& data, bool allow_subregs = false) {
    std::vector<Relation> out;
    size_t trials = data.initial_regs.size();
    std::unordered_set<int> changed_regs = compute_changed_bases(data);


    auto bitwise_generic = [&](std::function<uint64_t(uint64_t, uint64_t)> op, const std::string& op_name) {
        for (int r1 : changed_regs) {
            for (int r2 : Simulator::TRACKED_REGS) {
                if (r1 == r2) continue;
                auto pred = [&](size_t t) {
                    uint64_t f = data.final_regs[t].at(r1);
                    uint64_t i1 = data.initial_regs[t].at(r1);
                    uint64_t i2 = data.initial_regs[t].at(r2);
                    return f == op(i1, i2);
                    };
                if (all_trials_match(trials, pred)) {
                    std::string lhs = Simulator::reg_name(r1);
                    std::string rhs = "init_" + Simulator::reg_name(r1) + " " + op_name + " init_" + Simulator::reg_name(r2);
                    out.push_back({ lhs, rhs, 0, true });
                }
            }
        }
        };

    bitwise_generic(std::bit_and<uint64_t>(), "&");
    bitwise_generic(std::bit_or<uint64_t>(), "|");
    bitwise_generic(std::bit_xor<uint64_t>(), "^");


    for (int reg_id : changed_regs) {
        std::string reg_name = Simulator::reg_name(reg_id);
        uint64_t constant;


        auto compute_xor_const = [&](size_t t) {
            return data.final_regs[t].at(reg_id) ^ data.initial_regs[t].at(reg_id);
            };
        if (is_stable_value(trials, compute_xor_const, constant) && constant != 0) {

            bool subreg_only = false;
            std::string subreg_name;
            uint64_t subreg_mask = 0;
            auto subregs = get_subregs_for(reg_id);
            for (const auto& sub : subregs) {
                if (sub.mask == 0xFFFFFFFFULL) {
                    auto pred_sub = [&](size_t t) {
                        uint64_t f = extract_masked(data.final_regs[t], reg_id, sub.mask);
                        uint64_t i = extract_masked(data.initial_regs[t], reg_id, sub.mask);
                        return f == (i ^ (constant & sub.mask));
                        };
                    if (all_trials_match(trials, pred_sub)) {
                        subreg_only = true;
                        subreg_name = sub.name;
                        subreg_mask = sub.mask;
                        break;
                    }
                }
            }
            if (subreg_only) {
                out.push_back({ subreg_name, "init_" + subreg_name + " ^ 0x" + to_hex(constant & subreg_mask), 0, true });
            }
            else {
                out.push_back({ reg_name, "init_" + reg_name + " ^ 0x" + to_hex(constant), 0, true });
            }
        }


        auto compute_and_const = [&](size_t t) {
            uint64_t f = data.final_regs[t].at(reg_id);
            uint64_t i = data.initial_regs[t].at(reg_id);
            return f | (~i);
            };
        if (is_stable_value(trials, compute_and_const, constant) && constant != 0xFFFFFFFFFFFFFFFFULL) {
            auto pred_and = [&](size_t t) {
                uint64_t f = data.final_regs[t].at(reg_id);
                uint64_t i = data.initial_regs[t].at(reg_id);
                return f == (i & constant);
                };
            if (all_trials_match(trials, pred_and)) {

                bool subreg_only = false;
                std::string subreg_name;
                uint64_t subreg_mask = 0;
                auto subregs = get_subregs_for(reg_id);
                for (const auto& sub : subregs) {
                    if (sub.mask == 0xFFFFFFFFULL) {
                        auto pred_sub = [&](size_t t) {
                            uint64_t f = extract_masked(data.final_regs[t], reg_id, sub.mask);
                            uint64_t i = extract_masked(data.initial_regs[t], reg_id, sub.mask);
                            return f == (i & (constant & sub.mask));
                            };
                        if (all_trials_match(trials, pred_sub)) {
                            subreg_only = true;
                            subreg_name = sub.name;
                            subreg_mask = sub.mask;
                            break;
                        }
                    }
                }
                if (subreg_only) {
                    out.push_back({ subreg_name, "init_" + subreg_name + " & 0x" + to_hex(constant & subreg_mask), 0, true });
                }
                else {
                    out.push_back({ reg_name, "init_" + reg_name + " & 0x" + to_hex(constant), 0, true });
                }
            }
        }
    }

    if (!allow_subregs) return out;

    struct VReg { int base_reg; std::string name; uint64_t mask; };
    std::vector<VReg> vregs;
    for (int r : Simulator::TRACKED_REGS) {
        auto subs = get_subregs_for(r);
        for (auto& s : subs) vregs.push_back({ s.base_reg, s.name, s.mask });
    }
    size_t N = vregs.size();

    std::vector<size_t> changed_sub_indices;
    for (size_t i = 0; i < N; ++i) {
        if (changed_regs.count(vregs[i].base_reg) == 0) continue;
        int64_t sub_delta;
        auto fn_sub = [&](size_t t) {
            uint64_t ff = extract_masked(data.final_regs[t], vregs[i].base_reg, vregs[i].mask);
            uint64_t ii = extract_masked(data.initial_regs[t], vregs[i].base_reg, vregs[i].mask);
            return static_cast<int64_t>(ff - ii);
            };
        if (!is_stable_value(trials, fn_sub, sub_delta) || sub_delta != 0) {
            changed_sub_indices.push_back(i);
        }
    }

    if (changed_sub_indices.empty()) return out;

    auto bitwise_generic_sub = [&](std::function<uint64_t(uint64_t, uint64_t)> op, const std::string& op_name) {
        for (size_t ci : changed_sub_indices) {
            size_t i = ci;
            for (size_t j = 0; j < N; ++j) {
                if (i == j) continue;
                auto pred = [&](size_t t) {
                    uint64_t f = extract_masked(data.final_regs[t], vregs[i].base_reg, vregs[i].mask);
                    uint64_t i1 = extract_masked(data.initial_regs[t], vregs[i].base_reg, vregs[i].mask);
                    uint64_t i2 = extract_masked(data.initial_regs[t], vregs[j].base_reg, vregs[j].mask);
                    return f == op(i1, i2);
                    };
                if (all_trials_match(trials, pred)) {
                    out.push_back({ vregs[i].name, "init_" + vregs[i].name + " " + op_name + " init_" + vregs[j].name, 0, true });
                }
            }
        }
        };

    bitwise_generic_sub(std::bit_and<uint64_t>(), "&");
    bitwise_generic_sub(std::bit_or<uint64_t>(), "|");
    bitwise_generic_sub(std::bit_xor<uint64_t>(), "^");


    for (size_t ci : changed_sub_indices) {
        size_t i = ci;
        uint64_t constant;
        auto compute_xor = [&](size_t t) {
            return extract_masked(data.final_regs[t], vregs[i].base_reg, vregs[i].mask) ^
                extract_masked(data.initial_regs[t], vregs[i].base_reg, vregs[i].mask);
            };
        if (is_stable_value(trials, compute_xor, constant) && constant != 0) {
            out.push_back({ vregs[i].name, "init_" + vregs[i].name + " ^ 0x" + to_hex(constant & vregs[i].mask), 0, true });
        }
        auto compute_and = [&](size_t t) {
            uint64_t f = extract_masked(data.final_regs[t], vregs[i].base_reg, vregs[i].mask);
            uint64_t in = extract_masked(data.initial_regs[t], vregs[i].base_reg, vregs[i].mask);
            return f | (~in);
            };
        if (is_stable_value(trials, compute_and, constant) && constant != vregs[i].mask) {
            auto pred_and = [&](size_t t) {
                uint64_t f = extract_masked(data.final_regs[t], vregs[i].base_reg, vregs[i].mask);
                uint64_t in = extract_masked(data.initial_regs[t], vregs[i].base_reg, vregs[i].mask);
                return f == (in & constant);
                };
            if (all_trials_match(trials, pred_and)) {
                out.push_back({ vregs[i].name, "init_" + vregs[i].name + " & 0x" + to_hex(constant & vregs[i].mask), 0, true });
            }
        }
    }

    return out;
}

// ---------------- Unary Special Operations ----------------
inline std::vector<Relation> find_unary_special(const SimulationData& data) {
    std::vector<Relation> out;
    size_t trials = data.initial_regs.size();
    std::unordered_set<int> changed_regs = compute_changed_bases(data);

    for (int reg_id : changed_regs) {
        std::string reg_name = Simulator::reg_name(reg_id);

        auto pred_not = [&](size_t t) {
            uint64_t f = data.final_regs[t].at(reg_id);
            uint64_t i = data.initial_regs[t].at(reg_id);
            return f == ~i;
            };
        if (all_trials_match(trials, pred_not)) {
            out.push_back({ reg_name, "~init_" + reg_name, 0, true });
            continue;
        }

        auto pred_neg = [&](size_t t) {
            uint64_t f = data.final_regs[t].at(reg_id);
            uint64_t i = data.initial_regs[t].at(reg_id);
            return f == static_cast<uint64_t>(-static_cast<int64_t>(i));
            };
        if (all_trials_match(trials, pred_neg)) {
            out.push_back({ reg_name, "-init_" + reg_name, 0, true });
            continue;
        }
    }
    return out;
}

// ---------------- Shift Operations ----------------
inline std::vector<Relation> find_shift_operations(const SimulationData& data, bool allow_subregs = true) {
    std::vector<Relation> out;
    size_t trials = data.initial_regs.size();
    std::unordered_set<int> changed_regs = compute_changed_bases(data);

    // Fixed shifts for 64-bit
    for (int reg_id : changed_regs) {
        std::string reg_name = Simulator::reg_name(reg_id);

        for (int k = 1; k < 64; ++k) {
            auto pred_shl = [&](size_t t) {
                uint64_t f = data.final_regs[t].at(reg_id);
                uint64_t i = data.initial_regs[t].at(reg_id);
                return f == (i << k);
                };
            if (all_trials_match(trials, pred_shl)) {
                out.push_back({ reg_name, "init_" + reg_name + " << " + std::to_string(k), 0, true });
                break;
            }

            auto pred_shr = [&](size_t t) {
                uint64_t f = data.final_regs[t].at(reg_id);
                uint64_t i = data.initial_regs[t].at(reg_id);
                return f == (i >> k);
                };
            if (all_trials_match(trials, pred_shr)) {
                out.push_back({ reg_name, "init_" + reg_name + " >> " + std::to_string(k), 0, true });
                break;
            }

            auto pred_sar = [&](size_t t) {
                uint64_t f = data.final_regs[t].at(reg_id);
                uint64_t i = data.initial_regs[t].at(reg_id);
                return f == static_cast<uint64_t>(static_cast<int64_t>(i) >> k);
                };
            if (all_trials_match(trials, pred_sar)) {
                out.push_back({ reg_name, "init_" + reg_name + " sar " + std::to_string(k), 0, true });
                break;
            }

            auto pred_ror = [&](size_t t) {
                uint64_t f = data.final_regs[t].at(reg_id);
                uint64_t i = data.initial_regs[t].at(reg_id);
                return f == (i >> k | i << (64 - k));
                };
            if (all_trials_match(trials, pred_ror)) {
                out.push_back({ reg_name, "init_" + reg_name + " ror " + std::to_string(k), 0, true });
                break;
            }
        }
    }

    // Variable rotate by CL for 64-bit
    for (int dest : changed_regs) {
        std::string reg_name = Simulator::reg_name(dest);

        auto pred_ror_cl = [&](size_t t) {
            uint64_t f = data.final_regs[t].at(dest);
            uint64_t i = data.initial_regs[t].at(dest);
            uint64_t clv = data.initial_regs[t].at(UC_X86_REG_RCX) & 0xFFULL;
            clv &= 63ULL;  // mod 64 for 64-bit
            if (clv == 0) return true;
            uint64_t rotated = (i >> clv) | (i << (64ULL - clv));
            return f == rotated;
            };
        if (all_trials_match(trials, pred_ror_cl)) {
            out.push_back({ reg_name, "ror(init_" + reg_name + ", CL)", 0, true });
        }

        auto pred_rol_cl = [&](size_t t) {
            uint64_t f = data.final_regs[t].at(dest);
            uint64_t i = data.initial_regs[t].at(dest);
            uint64_t clv = data.initial_regs[t].at(UC_X86_REG_RCX) & 0xFFULL;
            clv &= 63ULL;
            if (clv == 0) return true;
            uint64_t rotated = (i << clv) | (i >> (64ULL - clv));
            return f == rotated;
            };
        if (all_trials_match(trials, pred_rol_cl)) {
            out.push_back({ reg_name, "rol(init_" + reg_name + ", CL)", 0, true });
        }
    }

    if (allow_subregs) {
        // Subregs version for ROR (improved)
        struct VReg { int base_reg; std::string name; uint64_t mask; uint64_t bits; };  // bits for shift width
        std::vector<VReg> vregs;
        for (int r : changed_regs) {
            auto subs = get_subregs_for(r);
            for (auto& s : subs) {
                uint64_t bits = (s.mask == 0xFFULL) ? 8 : (s.mask == 0xFFFFULL) ? 16 : 32;
                vregs.push_back({ s.base_reg, s.name, s.mask, bits });
            }
        }

        // Compute changed subregs
        size_t N_sub = vregs.size();
        std::vector<size_t> changed_sub_indices;
        for (size_t i = 0; i < N_sub; ++i) {
            int64_t sub_delta;
            auto fn_sub = [&](size_t t) {
                uint64_t ff = extract_masked(data.final_regs[t], vregs[i].base_reg, vregs[i].mask);
                uint64_t ii = extract_masked(data.initial_regs[t], vregs[i].base_reg, vregs[i].mask);
                return static_cast<int64_t>(ff - ii);
                };
            if (!is_stable_value(trials, fn_sub, sub_delta) || sub_delta != 0) {
                changed_sub_indices.push_back(i);
            }
        }

        if (!changed_sub_indices.empty()) {
            for (size_t ci : changed_sub_indices) {
                size_t i = ci;
                auto& vreg = vregs[i];
                for (int k = 1; k < static_cast<int>(vreg.bits); ++k) {
                    auto pred_ror = [&](size_t t) {
                        uint64_t f = extract_masked(data.final_regs[t], vreg.base_reg, vreg.mask);
                        uint64_t in = extract_masked(data.initial_regs[t], vreg.base_reg, vreg.mask);
                        uint64_t shifted = ((in >> k) | (in << (vreg.bits - k))) & vreg.mask;
                        return f == shifted;
                        };
                    if (all_trials_match(trials, pred_ror)) {
                        out.push_back({ vreg.name, "init_" + vreg.name + " ror " + std::to_string(k), 0, true });
                        break;
                    }
                }
            }
        }
    }

    return out;
}

// ---------------- Memory Relations ----------------
inline std::vector<Relation> find_memory_relations(const SimulationData& data) {
    size_t trials = data.initial_regs.size();
    size_t num_accesses = data.memory_accesses.empty() ? 0 : data.memory_accesses[0].size();
    std::vector<Relation> out;

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
    std::unordered_set<int> changed_regs = compute_changed_bases(data);

    for (int reg_id : changed_regs) {
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
    auto end_it = std::unique(out.begin(), out.end());
    out.erase(end_it, out.end());
    return out;
}

// ---------------- Analyzer Policy for Modularity ----------------
struct AnalyzerPolicy {
    std::string name;
    std::function<std::vector<Relation>(const SimulationData&)> analyzer_func;
    bool allow_subregs = true;
};

// ---------------- Aggregation ----------------
inline std::vector<Relation> find_constant_relations(Simulator& sim,
    const std::vector<uint8_t>& code, int trials = 5)
{
    auto data = run_simulations(sim, code, trials);
    if (!is_access_count_consistent(data)) return {};

    // Modular list of analyzers
    std::vector<AnalyzerPolicy> policies = {
        {"register_deltas", [&](const SimulationData& d) { return find_register_relations(d, true); }, true},
        {"register_register_ops", [&](const SimulationData& d) { return find_register_register_operations(d, true); }, true},
        {"unary_special", [&](const SimulationData& d) { return find_unary_special(d); }},
        {"shifts", [&](const SimulationData& d) { return find_shift_operations(d, true); }, true},
        {"bitwise_ops", [&](const SimulationData& d) { return find_bitwise_operations(d, true); }, true},
        {"memory_relations", [&](const SimulationData& d) { return find_memory_relations(d); }},
        {"register_memory_ops", [&](const SimulationData& d) { return find_register_memory_operations(d); }},
    };

    std::vector<Relation> relations;
    for (const auto& policy : policies) {
        auto rels = policy.analyzer_func(data);
        relations.insert(relations.end(), rels.begin(), rels.end());
    }

    // Fallback to subregs if nothing found
    if (relations.empty()) {
        for (const auto& policy : policies) {
            if (policy.allow_subregs) {
                auto sub_analyzer = [&](const std::string& pname) -> std::vector<Relation> {
                    if (pname == "register_deltas") return find_register_relations(data, true);
                    if (pname == "register_register_ops") return find_register_register_operations(data, true);
                    if (pname == "shifts") return find_shift_operations(data, true);
                    // Removed bitwise_ops subregs call since now included in main
                    return {};
                    };
                auto sub_rels = sub_analyzer(policy.name);
                relations.insert(relations.end(), sub_rels.begin(), sub_rels.end());
            }
        }
    }

    auto relation_cmp = [](const Relation& a, const Relation& b) {
        if (a.lhs != b.lhs) return a.lhs < b.lhs;
        if (a.rhs != b.rhs) return a.rhs < b.rhs;
        if (a.delta != b.delta) return a.delta < b.delta;
        return a.valid < b.valid;
        };

    std::sort(relations.begin(), relations.end(), relation_cmp);

    relations.erase(std::unique(relations.begin(), relations.end(),
        [](const Relation& a, const Relation& b) {
            return a.lhs == b.lhs && a.rhs == b.rhs && a.delta == b.delta;
        }), relations.end());

    relations.erase(std::remove_if(relations.begin(), relations.end(),
        [](const Relation& r) {
            if (!r.valid) return true;
            if (r.lhs == r.rhs && r.delta == 0) return true;
            return false;
        }), relations.end());

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
        << " -> 0x" << rc.new_value << std::dec << "\n";

    std::cout << "--- Memory Accesses ---\n";
    for (const auto& ma : result.mem_accesses) {
        std::cout << (ma.is_write ? "[WRITE] " : "[READ] ")
            << "0x" << std::hex << ma.address
            << " val=0x" << ma.value;
        if (ma.source_reg != -1)
            std::cout << " (from reg: " << Simulator::reg_name(ma.source_reg) << ")";
        std::cout << std::dec << "\n";
    }

    std::cout << "--- Constant Relations ---\n";
    for (const auto& r : result.relations) {
        if (!r.valid) continue;
        if (r.lhs == r.rhs && r.delta == 0) continue;
        std::cout << r.lhs << " = " << r.rhs;
        if (r.delta > 0) std::cout << " + 0x" << std::hex << r.delta;
        else if (r.delta < 0) std::cout << " - 0x" << std::hex << -r.delta;
        std::cout << std::dec << "\n";
    }
}