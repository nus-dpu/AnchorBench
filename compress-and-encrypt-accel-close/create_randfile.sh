#!/bin/bash

dd if=/dev/urandom bs=4M count=1 | base64 > input.dat