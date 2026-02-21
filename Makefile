CC=gcc
CFLAGS=-Wall -g -Iinclude
LIBS=-lcrypto

# Objetos (archivos temporales de compilacion)
UTILS_OBJ=src/mlkem_utils.o

all: server_app client_app

# Compilar el servidor
server_app: src/server.o $(UTILS_OBJ)
	$(CC) $(CFLAGS) src/server.o $(UTILS_OBJ) -o server_app $(LIBS)

# Compilar el cliente
client_app: src/client.o $(UTILS_OBJ)
	$(CC) $(CFLAGS) src/client.o $(UTILS_OBJ) -o client_app $(LIBS)

# Regla generica para convertir archivos .c en .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o server_app client_app
