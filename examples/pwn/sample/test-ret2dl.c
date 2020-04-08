#include <unistd.h>

void vuln(void) {
  char buf[0x20];
  read(0, buf, 0x100);
}

int main(void) {
  vuln();
  return 0;
}
