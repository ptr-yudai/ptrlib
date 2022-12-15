all:
	gcc -Wl,-z,lazy,-z,relro test-robot.c -o test-robot.x64 -fno-stack-protector -no-pie
	gcc -Wl,-z,now,-z,relro test-robot.c -o test-robot.relro.x64 -fno-stack-protector -no-pie

	gcc -Wl,-z,lazy,-z,relro test-ret2dl.c -o test-ret2dl.x86 -fno-stack-protector -no-pie -m32
	gcc -Wl,-z,lazy,-z,relro test-ret2dl.c -o test-ret2dl.relro.x86 -fno-stack-protector -no-pie -m32
