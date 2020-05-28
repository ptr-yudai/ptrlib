#include <stdio.h>

unsigned int target = 0;

int main(void)
{
  char buffer[0x200];

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  printf("target: %p\n", &target);
  fgets(buffer, 0x200, stdin);
  printf(buffer);

  if (target == 0xdeadbeef) {
    puts("OK");
  } else {
    puts("NG");
  }
}
