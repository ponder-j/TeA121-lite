static void write_index(int index) {
    char buffer[4];
    buffer[index] = 1;
}

int main(void) {
    write_index(4);
    return 0;
}
