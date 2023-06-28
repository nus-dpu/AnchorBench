#!/bin/bash

dd if=/dev/urandom bs=1M count=1 | base64 > SHA.dat