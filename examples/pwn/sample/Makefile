all:
	gcc -Wl,-z,lazy,-z,relro test-robot.c -o test-robot -fno-stack-protector -no-pie
	gcc -Wl,-z,now,-z,relro test-robot.c -o test-robot.relro -fno-stack-protector -no-pie
