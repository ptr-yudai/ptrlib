#include <unistd.h>

int main() {
  char buf[0x20];
  read(0, buf, 0x100);
  write(1, "Bye!\n", 5);
  return 0;
}
