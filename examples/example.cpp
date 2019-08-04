#include <map>

using int_map = std::map<int, int>;

int bar(int i, const int_map& m)
{
    if (i == 100)
    {
        throw std::runtime_error("oops");
    }

    try {
        return m.at(i);
    }
    catch (std::out_of_range& e)
    {
        return -1;
    }
}

int main() {
    int_map m;
    m[1] = 1;
    if (bar(2, m) == -1)
    {
        return 1;
    }
}
