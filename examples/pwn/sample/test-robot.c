#include <stdio.h>
#include <unistd.h>

__attribute__((constructor))
void setup(void) {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
}

int main() {
  char buf[0x20];
  read(0, buf, 0x100);
  puts("Bye!");
  return 0;
}
