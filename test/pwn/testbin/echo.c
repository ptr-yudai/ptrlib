#include <unistd.h>

int main(void)
{
  int s;
  char buf[0x400];

  while(1) {
    if ((s = read(0, buf, 0x400)) <= 0) break;
    write(1, buf, s);
  }

  return 0;
}
