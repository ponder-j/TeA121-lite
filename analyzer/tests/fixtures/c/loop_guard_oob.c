extern int external_condition;

int main(void) {
    int buffer[10];
    for (int i = 0; i <= 100; i++) {
        if (external_condition) {
            break;
        }
        buffer[i] = i;
    }
    return 0;
}
