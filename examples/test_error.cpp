#include <cornerstone/cornerstone.hpp>
#include <iostream>
#include <variant>

using namespace cstn;

int main() {
    std::variant<int, Error> v = ErrorEnum::InitFailure;

    Error e = std::get<Error>(v);

    std::cout << "e.value = " << (int)e.value << "\n";
    return 0;
}