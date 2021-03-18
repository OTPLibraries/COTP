#!/bin/bash
# Build the C dependencies, and the program, first
echo Building C
gcc -O0 -g3 -Wall -c ../*.c main.c
gcc -O0 -g3 -Wall -o test_c otpuri.o cotp.o main.o -lcrypto -lm