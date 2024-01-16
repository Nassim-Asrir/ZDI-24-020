all:
	gcc exploit.c -o exploit -lpthread -Wall

clean:
	rm -f exploit
