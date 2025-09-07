#include <iostream>
#include "simulator.h"
#include "Prediction.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <hex>\n";
        return 1;
    }

    std::string hex;
    for (int i = 1; i < argc; i++) hex += argv[i];

    auto code = Simulator::hex_to_bytes(hex);
    if (code.empty()) {
        std::cerr << "No code\n";
        return 1;
    }

    Simulator sim;
    RegMap init_regs = Simulator::make_random_regs();
    RegMap final_regs;
    sim.emulate(code, init_regs, final_regs);

    PredictionList predictions;

    for (auto& [reg_id, final_val] : final_regs) {
        Prediction p;
        p.dest.type = Operand::Type::REG;
        p.dest.reg = Simulator::reg_name(reg_id);

        uint64_t init_val = init_regs[reg_id];

        if (init_val != final_val) {
     
            p.src.type = Operand::Type::IMM;
            p.src.imm = final_val;
            p.op = Operation::NONE;
            predictions.add(p);
        }
    }

    std::cout << "\n--- Memory accesses ---\n";
    for (auto& m : sim.mem_accesses) {
        std::cout << (m.is_write ? "[WRITE] " : "[READ] ")
            << "0x" << std::hex << m.addr
            << " val=0x" << m.value
            << (m.reg_src != -1 ? " reg value : " + Simulator::reg_name(m.reg_src) : "")
            << "\n";
        Prediction p;


        int closest_reg = -1;
        uint64_t min_diff = UINT64_MAX;
        for (auto& [r_id, r_val] : init_regs) {
            uint64_t diff = (m.addr > r_val) ? (m.addr - r_val) : (r_val - m.addr);
            if (diff < min_diff) {
                min_diff = diff;
                closest_reg = r_id;
            }
        }

        if (closest_reg != -1) {
            p.dest.type = Operand::Type::MEM;
            p.dest.mem = "[mem]";
            p.src.type = Operand::Type::REG;
            p.src.reg = Simulator::reg_name(closest_reg);
            p.op = (m.addr > init_regs.at(closest_reg)) ? Operation::ADD : Operation::SUB;
            p.src.imm = min_diff;
            predictions.add(p);
        }



    }

    predictions.print_all();

    std::cout << "\n--- Checking predictions over 10 simulations ---\n";

    for (int k = 0; k < 10; ++k) {
        RegMap test_regs = Simulator::make_random_regs();
        RegMap test_final;
        sim.emulate(code, test_regs, test_final);

        std::cout << "Run " << k + 1 << ":\n";

        for (auto& p : predictions.get_all()) {
            bool correct = false;
            uint64_t dest_val;
            if (p.src.type != Operand::Type::MEM)
                dest_val  = test_final.at(p.dest_id());

            if (p.src.type ==Operand::Type::REG ) {
                uint64_t src_val = test_regs.at(reg_name_to_id(p.src.reg));
                switch (p.op) {
                case Operation::ADD: if (dest_val == src_val + p.src.imm) correct = true; break;
                case Operation::SUB: if (dest_val == src_val - p.src.imm) correct = true; break;
                case Operation::MUL: if (dest_val == src_val * p.src.imm) correct = true; break;
                case Operation::DIV: if (src_val != 0 && dest_val == src_val / p.src.imm) correct = true; break;
                case Operation::XOR: if (dest_val == src_val ^ p.src.imm) correct = true; break;
                case Operation::SHL: if (dest_val == src_val << p.src.imm) correct = true; break;
                case Operation::SHR: if (dest_val == src_val >> p.src.imm) correct = true; break;
                default: break;
                }
            }
            else if (p.src.type == Operand::Type::IMM) {
                if (dest_val == p.src.imm) correct = true;
            }

            p.print();
            std::cout << " -> " << (correct ? "OK" : "FAIL") << "\n";

            if (!correct) {
               // p.update_guess(test_regs, test_final);
            }
        }

        std::cout << "----------------------\n";
    }
}
