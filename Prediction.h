#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <unordered_map>
#include "Simulator.h"

enum class Operation {
    NONE,
    ADD,
    SUB,
    MUL,
    DIV
};

inline int reg_name_to_id(const std::string& name) {
    static std::unordered_map<std::string, int> reg_map = {
        {"RAX", UC_X86_REG_RAX}, {"RBX", UC_X86_REG_RBX},
        {"RCX", UC_X86_REG_RCX}, {"RDX", UC_X86_REG_RDX},
        {"RSI", UC_X86_REG_RSI}, {"RDI", UC_X86_REG_RDI},
        {"RSP", UC_X86_REG_RSP}, {"RBP", UC_X86_REG_RBP},
        {"R8",  UC_X86_REG_R8},  {"R9",  UC_X86_REG_R9},
        {"R10", UC_X86_REG_R10}, {"R11", UC_X86_REG_R11},
        {"R12", UC_X86_REG_R12}, {"R13", UC_X86_REG_R13},
        {"R14", UC_X86_REG_R14}, {"R15", UC_X86_REG_R15}
    };
    auto it = reg_map.find(name);
    if (it != reg_map.end()) return it->second;
    return -1; 
}

class Prediction {
public:
    std::string dest;         
    std::string src_reg;      
    Operation op;             
    std::string value_or_mem; 

    Prediction() : op(Operation::NONE) {}

    void print() const {
        std::cout << dest << " = ";
        if (!src_reg.empty()) std::cout << src_reg << " ";
        switch (op) {
        case Operation::ADD: std::cout << "+"; break;
        case Operation::SUB: std::cout << "-"; break;
        case Operation::MUL: std::cout << "*"; break;
        case Operation::DIV: std::cout << "/"; break;
        default: break;
        }
        if (!value_or_mem.empty()) std::cout << value_or_mem;
        std::cout << "\n";
    }

    int dest_id() const { return reg_name_to_id(dest); }
    int src_id() const { return src_reg.empty() ? -1 : reg_name_to_id(src_reg); }
};

class PredictionList {
    std::vector<Prediction> preds;

public:
    void add(const Prediction& p) { preds.push_back(p); }

    void print_all() const {
        for (const auto& p : preds) p.print();
    }

    const std::vector<Prediction>& get_all() const { return preds; }
};
