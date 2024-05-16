#include <iostream>
#include "Repl.h"

using std::cout;
using std::endl;

int main() {
    cout << "Hello, World!" << endl;

    while(ReplBody()) { }
    return 0;
}