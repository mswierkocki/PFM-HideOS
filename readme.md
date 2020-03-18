# Packet filter module - Hide OS
Module loaded to kernel that edit on the fly system signatures by changing Window size and TTl. (2010y)

csum funtions are from  /usr/src/linux/include/asm/checksum.h

## usage
make -s
insmod modul.o
## Test
p0f -i lo
nmap -O localhost