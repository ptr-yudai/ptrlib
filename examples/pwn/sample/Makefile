all:
	gcc -Wl,-z,lazy,-z,relro test1.c -o test1 -fno-stack-protector -no-pie
	gcc -Wl,-z,lazy,-z,relro test2.c -o test2 -fno-stack-protector -no-pie -m32
