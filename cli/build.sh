#!/bin/bash
# Build the CLI dependencies, and the 'otp' CLI tool
echo "Building 'otp' CLI tool"
gcc -O0 -g3 -Wall -c ../*.c main.c
gcc -O0 -g3 -Wall -o otp-cli otpuri.o cotp.o main.o -lcrypto -lm
