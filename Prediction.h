#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <unordered_map>
#include <variant>
#include "Simulator.h"

enum class Operation {
    NONE, ADD, SUB, MUL, DIV, XOR, SHL, SHR
};

struct Operand {
    enum class Type { REG, MEM, IMM } type;
    std::string reg;   
    int id;
    uint64_t imm = 0;  
    std::string mem;   

    Operand() : type(Type::IMM), imm(0) {}
};
inline int reg_name_to_id(const std::string& name) {
    static std::unordered_map<std::string, int> reg_map = {
        {"RAX", UC_X86_REG_RAX}, {"EAX", UC_X86_REG_EAX}, {"AX", UC_X86_REG_AX}, {"AL", UC_X86_REG_AL}, {"AH", UC_X86_REG_AH},
        {"RBX", UC_X86_REG_RBX}, {"EBX", UC_X86_REG_EBX}, {"BX", UC_X86_REG_BX}, {"BL", UC_X86_REG_BL}, {"BH", UC_X86_REG_BH},
        {"RCX", UC_X86_REG_RCX}, {"ECX", UC_X86_REG_ECX}, {"CX", UC_X86_REG_CX}, {"CL", UC_X86_REG_CL}, {"CH", UC_X86_REG_CH},
        {"RDX", UC_X86_REG_RDX}, {"EDX", UC_X86_REG_EDX}, {"DX", UC_X86_REG_DX}, {"DL", UC_X86_REG_DL}, {"DH", UC_X86_REG_DH},
        {"RSI", UC_X86_REG_RSI}, {"ESI", UC_X86_REG_ESI}, {"SI", UC_X86_REG_SI}, {"SIL", UC_X86_REG_SIL},
        {"RDI", UC_X86_REG_RDI}, {"EDI", UC_X86_REG_EDI}, {"DI", UC_X86_REG_DI}, {"DIL", UC_X86_REG_DIL},
        {"RSP", UC_X86_REG_RSP}, {"ESP", UC_X86_REG_ESP}, {"SP", UC_X86_REG_SP}, {"SPL", UC_X86_REG_SPL},
        {"RBP", UC_X86_REG_RBP}, {"EBP", UC_X86_REG_EBP}, {"BP", UC_X86_REG_BP}, {"BPL", UC_X86_REG_BPL},
        {"R8", UC_X86_REG_R8}, {"R8D", UC_X86_REG_R8D}, {"R8W", UC_X86_REG_R8W}, {"R8B", UC_X86_REG_R8B},
        {"R9", UC_X86_REG_R9}, {"R9D", UC_X86_REG_R9D}, {"R9W", UC_X86_REG_R9W}, {"R9B", UC_X86_REG_R9B},
        {"R10", UC_X86_REG_R10}, {"R10D", UC_X86_REG_R10D}, {"R10W", UC_X86_REG_R10W}, {"R10B", UC_X86_REG_R10B},
        {"R11", UC_X86_REG_R11}, {"R11D", UC_X86_REG_R11D}, {"R11W", UC_X86_REG_R11W}, {"R11B", UC_X86_REG_R11B},
        {"R12", UC_X86_REG_R12}, {"R12D", UC_X86_REG_R12D}, {"R12W", UC_X86_REG_R12W}, {"R12B", UC_X86_REG_R12B},
        {"R13", UC_X86_REG_R13}, {"R13D", UC_X86_REG_R13D}, {"R13W", UC_X86_REG_R13W}, {"R13B", UC_X86_REG_R13B},
        {"R14", UC_X86_REG_R14}, {"R14D", UC_X86_REG_R14D}, {"R14W", UC_X86_REG_R14W}, {"R14B", UC_X86_REG_R14B},
        {"R15", UC_X86_REG_R15}, {"R15D", UC_X86_REG_R15D}, {"R15W", UC_X86_REG_R15W}, {"R15B", UC_X86_REG_R15B},
    };

    auto it = reg_map.find(name);
    if (it != reg_map.end()) return it->second;
    return -1;
}


class Prediction {
public:
    Operand dest;
    Operand src;
    Operation op = Operation::NONE;

    void print() const {
        auto print_operand = [](const Operand& o) {
            switch (o.type) {
            case Operand::Type::REG: std::cout << o.reg; break;
            case Operand::Type::IMM: std::cout << "0x" << std::hex << o.imm; break;
            case Operand::Type::MEM: std::cout << "[mem " + std::to_string(o.id) + "]"; break;
            }
            };

        print_operand(dest);
        std::cout << " = ";
        print_operand(src);
        switch (op) {
        case Operation::ADD: std::cout << " +"; break;
        case Operation::SUB: std::cout << " -"; break;
        case Operation::MUL: std::cout << " *"; break;
        case Operation::DIV: std::cout << " /"; break;
        case Operation::XOR: std::cout << " ^"; break;
        case Operation::SHL: std::cout << " <<"; break;
        case Operation::SHR: std::cout << " >>"; break;
        default: break;
        }
        std::cout << " " << src.imm;
        std::cout << "\n";
    }

    int dest_id() const {
        return dest.type == Operand::Type::REG ? reg_name_to_id(dest.reg) : -1;
    }

    int src_id() const {
        return src.type == Operand::Type::REG ? reg_name_to_id(src.reg) : -1;
    }

 
    void update_guess(const RegMap& test_regs, const RegMap& test_final) {
        uint64_t target = test_final.at(dest_id());

        uint64_t min_offset = UINT64_MAX;
        int closest_reg = -1;
        for (auto& [reg_id, val] : test_regs) {
            uint64_t diff = (target > val) ? (target - val) : (val - target);
            if (diff < min_offset) {
                min_offset = diff;
                closest_reg = reg_id;
            }
        }
        if (closest_reg != -1) {
            src.type = Operand::Type::REG;
            src.reg = Simulator::reg_name(closest_reg);
            src.imm = min_offset;
            op = (target > test_regs.at(closest_reg)) ? Operation::ADD : Operation::SUB;
        }
    }

};

class PredictionList {
    std::vector<Prediction> preds;

public:
    void add(const Prediction& p) {
        preds.push_back(p);
    }

    std::vector<Prediction>& get_all() { return preds; }
    const std::vector<Prediction>& get_all() const { return preds; }

    void print_all() const {
        for (const auto& p : preds) p.print();
    }
};
