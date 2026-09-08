static void write_index(int index) {
    char buffer[4];
    buffer[index] = 1;
}

int main(void) {
    write_index(3);
    return 0;
}
