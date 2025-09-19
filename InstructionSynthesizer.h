#pragma once
#include "simulator.h"
#include "analysis.h"
#include <string>
#include <vector>
#include <iostream>
#include <cstring>
#include <algorithm>
#include <XEDParse.h>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <cctype>
#include <sstream>

struct SynthesizedInstr {
    std::string asm_code;
    std::vector<uint8_t> machine_code;
};

class InstructionSynthesizer {
public:
    SynthesizedInstr synthesize(const ExecutionResult& result,
        const RegMap& init_regs,
        const RegMap& final_regs)
    {
        SynthesizedInstr out;
        std::vector<std::string> initial_instructions;
        std::vector<std::string> update_instructions;

        // 1) Memory load detection
        for (auto& rc : result.reg_changes) {
            std::string dst = rc.name;
            bool handled = false;

            for (auto& kv : init_regs) {
                std::string src = Simulator::reg_name(kv.first);
                for (auto& ma : result.mem_accesses) {
                    if ((kv.second == ma.address) && (rc.new_value == ma.value) && !ma.is_write) {
                        update_instructions.push_back("mov " + to_lower(dst) + ", [" + to_lower(src) + "]");
                        handled = true;
                        break;
                    }
                }
                if (handled) break;
            }
        }

        // 2) Subregister handling (similar to before)
        for (auto& rc : result.reg_changes) {
            std::string dst = rc.name;
            auto subregs = get_subreg_names(dst);
            bool sub_handled = false;
            for (const std::string& sub_dst : subregs) {
                for (const auto& rel : result.relations) {
                    if (!rel.valid) continue;
                    if (rel.lhs != sub_dst) continue;
                    std::string instr;
                    if (rel.rhs.find("init_" + sub_dst + " - ") == 0) {
                        size_t pos = ("init_" + sub_dst + " - ").length();
                        std::string src = rel.rhs.substr(pos);
                        if (src.find("init_") == 0) src = src.substr(5);
                        instr = "sub " + to_lower(sub_dst) + ", " + to_lower(src);
                        update_instructions.push_back(instr);
                        sub_handled = true;
                        break;
                    }
                    else if (rel.rhs.find("init_" + sub_dst + " + ") == 0) {
                        size_t pos = ("init_" + sub_dst + " + ").length();
                        std::string src = rel.rhs.substr(pos);
                        if (src.find("init_") == 0) src = src.substr(5);
                        instr = "add " + to_lower(sub_dst) + ", " + to_lower(src);
                        update_instructions.push_back(instr);
                        sub_handled = true;
                        break;
                    }
                    else if (rel.rhs == "init_" + sub_dst) {
                        if (rel.delta == 1) update_instructions.push_back("inc " + to_lower(sub_dst));
                        else if (rel.delta == -1) update_instructions.push_back("dec " + to_lower(sub_dst));
                        else if (rel.delta > 0) update_instructions.push_back("add " + to_lower(sub_dst) + ", " + imm_hex(rel.delta));
                        else if (rel.delta < 0) update_instructions.push_back("sub " + to_lower(sub_dst) + ", " + imm_hex(-rel.delta));
                        sub_handled = true;
                        break;
                    }
                    else if (rel.rhs == "~init_" + sub_dst) {
                        update_instructions.push_back("not " + to_lower(sub_dst));
                        sub_handled = true;
                        break;
                    }
                    else if (rel.rhs == "-init_" + sub_dst) {
                        update_instructions.push_back("neg " + to_lower(sub_dst));
                        sub_handled = true;
                        break;
                    }
                }
                if (sub_handled) break;
            }
        }

        // 3) Dependency graph for full-register relations
        std::unordered_map<std::string, Relation> rel_map;
        std::unordered_set<std::string> modified_regs;
        for (const auto& rel : result.relations) {
            if (!rel.valid) continue;
            if (rel.lhs.empty()) continue;
            if (rel.lhs.find("mem[") == 0) continue;
            rel_map[rel.lhs] = rel;
            modified_regs.insert(rel.lhs);
        }

        if (!rel_map.empty()) {
            // graph: node -> list of nodes that must come after this node
            // We'll add edge A -> B when relation A uses init_X and relation B modifies X
            std::unordered_map<std::string, std::vector<std::string>> graph;
            std::unordered_map<std::string, int> indeg;

            // ensure all nodes exist in indeg
            for (const auto& kv : rel_map) indeg[kv.first] = 0;

            for (const auto& kv : rel_map) {
                const std::string& A = kv.first; // relation A's lhs
                const Relation& relA = kv.second;
                auto inits = extract_init_tokens(relA.rhs);
                for (const auto& token : inits) {
                    // skip self-use (init_DST inside its own relation) - no ordering needed
                    if (token == A) continue;
                    // if some relation modifies 'token', then A must come before that modifier
                    if (rel_map.count(token)) {
                        // add edge A -> token_modifier
                        graph[A].push_back(token);
                        indeg[token] += 1;
                    }
                }
            }

            // Kahn's algorithm for topological sort
            std::queue<std::string> q;
            for (const auto& kv : indeg) if (kv.second == 0) q.push(kv.first);

            std::vector<std::string> topo_order;
            while (!q.empty()) {
                std::string n = q.front(); q.pop();
                topo_order.push_back(n);
                auto it = graph.find(n);
                if (it != graph.end()) {
                    for (const auto& m : it->second) {
                        indeg[m] -= 1;
                        if (indeg[m] == 0) q.push(m);
                    }
                }
            }

            // if a cycle exists (can't topo sort), fallback: try a safer fallback strategy
            if (topo_order.size() != indeg.size()) {
                // fallback: try to order so that unary modifiers (neg/not) come last if possible
                // collect unary modifiers
                std::vector<std::string> unary_mods;
                std::vector<std::string> others;
                for (const auto& kv : rel_map) {
                    const std::string& dst = kv.first;
                    const Relation& r = kv.second;
                    if (r.rhs == ("-init_" + dst) || r.rhs == ("~init_" + dst)) unary_mods.push_back(dst);
                    else others.push_back(dst);
                }
                topo_order.clear();
                // place others first, then unary_mods
                for (auto& x : others) topo_order.push_back(x);
                for (auto& x : unary_mods) topo_order.push_back(x);
            }

            // generate instructions following topo order
            for (const auto& dst : topo_order) {
                if (!rel_map.count(dst)) continue;
                const Relation& rel = rel_map[dst];
                auto instrs = gen_instructions_for_relation(rel, modified_regs);
                for (const auto& ins : instrs) update_instructions.push_back(ins);
            }
        }

        // 4) Memory writes
        for (auto& kv : init_regs) {
            std::string base = Simulator::reg_name(kv.first);
            for (auto& ma : result.mem_accesses) {
                if ((kv.second == ma.address) && ma.is_write && ma.source_reg != -1) {
                    std::string src = Simulator::reg_name(ma.source_reg);
                    update_instructions.push_back("mov [" + to_lower(base) + "], " + to_lower(src));
                }
            }
        }

        // 5) Memory relations
        for (auto& rel : result.relations) {
            if (rel.valid && rel.lhs.find("mem[") == 0) {
                std::string mem_addr = rel.lhs.substr(4, rel.lhs.size() - 5);
                std::string src = rel.rhs;
                src = replace_init_refs(src);
                if (src.find("mem[") != std::string::npos) continue;
                if (rel.delta == 0) update_instructions.push_back("mov [" + mem_addr + "], " + src);
                else update_instructions.push_back("mov [" + mem_addr + "], " + src);
            }
        }

        // finalize
        std::vector<std::string> instructions = initial_instructions;
        instructions.insert(instructions.end(), update_instructions.begin(), update_instructions.end());
        if (instructions.empty()) instructions.push_back("nop");

        out.asm_code = "";
        for (auto& instr : instructions) out.asm_code += instr + "\n";

        return assemble_and_return(out);
    }

private:
    // Extract tokens like R15, RDI from occurrences of "init_R15"
    static std::vector<std::string> extract_init_tokens(const std::string& s) {
        std::vector<std::string> out;
        size_t pos = 0;
        while (true) {
            size_t p = s.find("init_", pos);
            if (p == std::string::npos) break;
            size_t start = p + 5;
            size_t i = start;
            while (i < s.size() && (std::isalnum((unsigned char)s[i]) || s[i] == '_')) ++i;
            std::string token = s.substr(start, i - start);
            if (!token.empty()) out.push_back(token);
            pos = i;
        }
        return out;
    }

    // replace init_R... -> r...
    static std::string replace_init_refs(const std::string& s) {
        std::string out;
        size_t pos = 0;
        while (pos < s.size()) {
            size_t p = s.find("init_", pos);
            if (p == std::string::npos) {
                out += s.substr(pos);
                break;
            }
            out += s.substr(pos, p - pos);
            size_t start = p + 5;
            size_t i = start;
            while (i < s.size() && (std::isalnum((unsigned char)s[i]) || s[i] == '_')) ++i;
            std::string token = s.substr(start, i - start);
            if (!token.empty()) out += to_lower(token);
            else out += "init_";
            pos = i;
        }
        return out;
    }

    // generate asm for single relation
    static std::vector<std::string> gen_instructions_for_relation(const Relation& rel, const std::unordered_set<std::string>& /*modified_regs*/) {
        std::vector<std::string> out;
        std::string dst = rel.lhs;
        std::string rhs = rel.rhs;
        std::string rhs_repl = replace_init_refs(rhs);
        std::string dst_op = to_lower(dst);

        if (rhs == "0x0") {
            if (rel.delta > 0) out.push_back("add " + dst_op + ", " + imm_hex(rel.delta));
            else if (rel.delta < 0) out.push_back("sub " + dst_op + ", " + imm_hex(-rel.delta));
            else out.push_back("mov " + dst_op + ", 0");
            return out;
        }

        if (rhs == ("-init_" + dst)) {
            out.push_back("neg " + dst_op);
            return out;
        }
        if (rhs == ("~init_" + dst)) {
            out.push_back("not " + dst_op);
            return out;
        }

        std::string prefix = "init_" + dst + " + ";
        std::string prefix_sub = "init_" + dst + " - ";
        std::string prefix_xor = "init_" + dst + " ^ ";
        std::string prefix_and = "init_" + dst + " & ";
        std::string prefix_or = "init_" + dst + " | ";
        std::string prefix_shl = "init_" + dst + " << ";
        std::string prefix_shr = "init_" + dst + " >> ";
        std::string prefix_sar = "init_" + dst + " sar ";
        std::string prefix_ror = "init_" + dst + " ror ";

        if (rel.rhs.find(prefix) == 0) {
            std::string op_part = rel.rhs.substr(prefix.length());
            std::string op_repl = replace_init_refs(op_part);
            if (op_part.find("mem[") == 0) {
                std::string addr = op_part.substr(4, op_part.size() - 5);
                out.push_back("add " + dst_op + ", [" + addr + "]");
            }
            else {
                out.push_back("add " + dst_op + ", " + op_repl);
            }
            return out;
        }
        else if (rel.rhs.find(prefix_sub) == 0) {
            std::string op_part = rel.rhs.substr(prefix_sub.length());
            std::string op_repl = replace_init_refs(op_part);
            if (op_part.find("mem[") == 0) {
                std::string addr = op_part.substr(4, op_part.size() - 5);
                out.push_back("sub " + dst_op + ", [" + addr + "]");
            }
            else {
                out.push_back("sub " + dst_op + ", " + op_repl);
            }
            return out;
        }
        else if (rel.rhs.find(prefix_xor) == 0) {
            std::string op_part = rel.rhs.substr(prefix_xor.length());
            if (op_part.find("0x") == 0) out.push_back("xor " + dst_op + ", " + imm_hex(std::stoull(op_part, nullptr, 16)));
            else out.push_back("xor " + dst_op + ", " + replace_init_refs(op_part));
            return out;
        }
        else if (rel.rhs.find(prefix_and) == 0) {
            std::string op_part = rel.rhs.substr(prefix_and.length());
            if (op_part.find("0x") == 0) out.push_back("and " + dst_op + ", " + imm_hex(std::stoull(op_part, nullptr, 16)));
            else out.push_back("and " + dst_op + ", " + replace_init_refs(op_part));
            return out;
        }
        else if (rel.rhs.find(prefix_or) == 0) {
            std::string op_part = rel.rhs.substr(prefix_or.length());
            if (op_part.find("0x") == 0) out.push_back("or " + dst_op + ", " + imm_hex(std::stoull(op_part, nullptr, 16)));
            else out.push_back("or " + dst_op + ", " + replace_init_refs(op_part));
            return out;
        }
        else if (rel.rhs.find(prefix_shl) == 0) {
            std::string k = rel.rhs.substr(prefix_shl.length());
            try { int shift_val = std::stoi(k); out.push_back("shl " + dst_op + ", " + imm_hex(shift_val)); }
            catch (...) { out.push_back("shl " + dst_op + ", " + k); }
            return out;
        }
        else if (rel.rhs.find(prefix_shr) == 0) {
            std::string k = rel.rhs.substr(prefix_shr.length());
            try { int shift_val = std::stoi(k); out.push_back("shr " + dst_op + ", " + imm_hex(shift_val)); }
            catch (...) { out.push_back("shr " + dst_op + ", " + k); }
            return out;
        }
        else if (rel.rhs.find(prefix_sar) == 0) {
            std::string k = rel.rhs.substr(prefix_sar.length());
            try { int shift_val = std::stoi(k); out.push_back("sar " + dst_op + ", " + imm_hex(shift_val)); }
            catch (...) { out.push_back("sar " + dst_op + ", " + k); }
            return out;
        }
        else if (rel.rhs.find(prefix_ror) == 0) {
            std::string k = rel.rhs.substr(prefix_ror.length());
            try { int shift_val = std::stoi(k); out.push_back("ror " + dst_op + ", " + imm_hex(shift_val)); }
            catch (...) { out.push_back("ror " + dst_op + ", " + k); }
            return out;
        }

        if (rel.rhs.find("mem[") != std::string::npos) {
            std::string base = rel.rhs.substr(4, rel.rhs.size() - 5);
            if (rel.delta != 0) {
                std::string sign = (rel.delta > 0) ? " + " : " - ";
                out.push_back("mov " + dst_op + ", [" + base + sign + imm_hex(std::abs(rel.delta)) + "]");
            }
            else {
                out.push_back("mov " + dst_op + ", [" + base + "]");
            }
            return out;
        }

        if (rel.rhs == ("init_" + dst)) {
            if (rel.delta == 1) out.push_back("inc " + dst_op);
            else if (rel.delta == -1) out.push_back("dec " + dst_op);
            else if (rel.delta > 0) out.push_back("add " + dst_op + ", " + imm_hex(rel.delta));
            else if (rel.delta < 0) out.push_back("sub " + dst_op + ", " + imm_hex(-rel.delta));
            return out;
        }

        // Default: mov dst, rhs; then apply delta if any
        {
            std::string src = rhs_repl;
            if (dst_op != src) out.push_back("mov " + dst_op + ", " + src);
            if (rel.delta > 0) out.push_back("add " + dst_op + ", " + imm_hex(rel.delta));
            else if (rel.delta < 0) out.push_back("sub " + dst_op + ", " + imm_hex(-rel.delta));
        }

        return out;
    }

    static std::vector<std::string> get_subreg_names(const std::string& full_reg) {
        if (full_reg == "RAX") return { "EAX", "AX", "AL" };
        if (full_reg == "RBX") return { "EBX", "BX", "BL" };
        if (full_reg == "RCX") return { "ECX", "CX", "CL" };
        if (full_reg == "RDX") return { "EDX", "DX", "DL" };
        if (full_reg == "RSI") return { "ESI", "SI", "SIL" };
        if (full_reg == "RDI") return { "EDI", "DI", "DIL" };
        if (full_reg == "RSP") return { "ESP", "SP", "SPL" };
        if (full_reg == "RBP") return { "EBP", "BP", "BPL" };
        if (full_reg == "R8") return { "R8D", "R8W", "R8B" };
        if (full_reg == "R9") return { "R9D", "R9W", "R9B" };
        if (full_reg == "R10") return { "R10D", "R10W", "R10B" };
        if (full_reg == "R11") return { "R11D", "R11W", "R11B" };
        if (full_reg == "R12") return { "R12D", "R12W", "R12B" };
        if (full_reg == "R13") return { "R13D", "R13W", "R13B" };
        if (full_reg == "R14") return { "R14D", "R14W", "R14B" };
        if (full_reg == "R15") return { "R15D", "R15W", "R15B" };
        return {};
    }

    static std::string imm_hex(int64_t v) {
        char buf[64];
        if (v < 0) v = -v;
        snprintf(buf, sizeof(buf), "0x%llX", (long long)v);
        return std::string(buf);
    }

    static std::string to_hex(uint64_t v) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%llX", (long long)v);
        return std::string(buf);
    }

    static uint64_t ror(uint64_t val, int n) {
        return (val >> n) | (val << (64 - n));
    }

    static std::string to_lower(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) out.push_back(std::tolower((unsigned char)c));
        return out;
    }

    SynthesizedInstr assemble_and_return(SynthesizedInstr& instr) {
        SynthesizedInstr final;
        XEDPARSE parse;
        memset(&parse, 0, sizeof(parse));
        parse.x64 = true;
        parse.cip = 0x1000;
        for (auto& line : split_lines(instr.asm_code)) {
            std::string trimmed = line;
            trimmed.erase(0, trimmed.find_first_not_of(" \t"));
            trimmed.erase(trimmed.find_last_not_of(" \t") + 1);
            if (trimmed.empty()) continue;
            strcpy_s(parse.instr, sizeof(parse.instr), trimmed.c_str());
            if (XEDParseAssemble(&parse) == XEDPARSE_ERROR) {
                std::cerr << "Assembly failed for: " << trimmed << " - " << parse.error << "\n";
                final.machine_code.clear();
                continue;
            }
            final.machine_code.insert(final.machine_code.end(), parse.dest, parse.dest + parse.dest_size);
            final.asm_code += trimmed + "\n";
        }
        return final;
    }

    std::vector<std::string> split_lines(const std::string& str) {
        std::vector<std::string> lines;
        std::istringstream iss(str);
        std::string line;
        while (std::getline(iss, line)) {
            if (!line.empty()) lines.push_back(line);
        }
        return lines;
    }
};
