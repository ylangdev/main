const int magic_const = 42;
int initialized_var = 7;
int uninitialized_var;

int add_numbers(int a, int b) {
    return a + b + magic_const;
}

int main(void) {
    uninitialized_var = add_numbers(initialized_var, 3);
    return 0;
}
