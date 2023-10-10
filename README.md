# PacketGuard-XDP

First of all create a object file by running the following command:

`clang -O2 -g -Wall -target bpf -c dropipv4.c -o dropipv4.o`

Then build the go file:

`go build drop.go`

Finally run the script using the following command, you can chanage the network interface and port dynamically in the cmd terminal:

`sudo ./drop {network_interface} {PORT}`

example:

`sudo ./drop lo 4040`
