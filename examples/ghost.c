/* I'm a silly program that does nothing much on its own. */
/* Compile me with "gcc ghost.c -o ghost".                */

void there_is_a_ghost(void) {
    return;
}

int main(int argc, char *argv[]) {
    int i;
    for (i = 0; i < 10; i++) {
        there_is_a_ghost();
    }
    return 0;
}
