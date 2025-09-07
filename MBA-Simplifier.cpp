#include <iostream>
#include "simulator.h"
#include "Prediction.h"

int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "Usage: " << argv[0] << " <hex>\n"; return 1; }

    std::string hex;
    for (int i = 1; i < argc; i++) hex += argv[i];

    auto code = Simulator::hex_to_bytes(hex);
    if (code.empty()) { std::cerr << "No code\n"; return 1; }

    Simulator sim;


    RegMap init_regs = Simulator::make_random_regs();
    RegMap final_regs;
    sim.emulate(code, init_regs, final_regs);

    PredictionList predictions;
    for (auto& r : final_regs) {
        for (auto& i : init_regs) {
            if ((r.first == i.first) && (r.second == i.second)) break;

            Prediction p;
            p.dest = Simulator::reg_name(r.first);

            if ((i.second == r.second) && !(i.first == r.first)) {
                p.src_reg = Simulator::reg_name(i.first);
                p.op = Operation::NONE;
                p.value_or_mem = "";
                predictions.add(p);
            }

            if ((i.first == r.first) && !(i.second == r.second)) {
                p.src_reg = "";
                p.op = Operation::NONE;
                p.value_or_mem = "0x" + std::to_string(r.second);
                predictions.add(p);
            }
        }
    }

    predictions.print_all();
    std::cout << "\n--- Checking predictions over 10 simulations ---\n";

    for (int k = 0; k < 10; ++k) {
        RegMap test_regs = Simulator::make_random_regs();
        RegMap test_final;
        sim.emulate(code, test_regs, test_final);

        std::cout << "Run " << k + 1 << ":\n";
        for (const auto& p : predictions.get_all()) {
            bool correct = false;


            if (!p.value_or_mem.empty() && p.src_reg.empty()) {
                uint64_t expected = std::stoull(p.value_or_mem, nullptr, 16);
                if (test_final[p.dest_id()] == expected) correct = true;
            }


            if (!p.src_reg.empty()) {
                if (test_final[p.dest_id()] == test_final[p.src_id()]) correct = true;
            }

            std::cout << p.dest << " prediction ";
            p.print();
            std::cout << " -> " << (correct ? "OK" : "FAIL") << "\n";
        }
        std::cout << "----------------------\n";
    }
}
