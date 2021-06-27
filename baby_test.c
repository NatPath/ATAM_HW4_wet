#include <stdio.h>

void foo() {
    printf("please work!");
}
static void kill_me(){
    printf("don't");
}
int main() {
    foo();
    return 0;
}
