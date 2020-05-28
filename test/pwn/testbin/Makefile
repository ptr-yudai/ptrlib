all:
	gcc -Wno-format-security -Wl,-z,lazy,-z,relro fsb.c -o test_fsb.x64 -fno-stack-protector -no-pie -O0
	gcc -Wno-format-security -Wl,-z,lazy,-z,relro fsb.c -o test_fsb.x86 -fno-stack-protector -no-pie -O0 -m32
	gcc echo.c -o test_echo.x64
	strip --strip-all test_*
