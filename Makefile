all: aes

aes: aes.o
	g++ -o aes aes.o -lcryptopp

clean:
	rm -f aes.o aes
