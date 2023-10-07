#!/bin/bash

docker build -t jamesob/fscm-test-ssh-debian -f tests/integration/dockerfiles/debian.Dockerfile .
docker build -t jamesob/fscm-test-ssh-arch -f tests/integration/dockerfiles/arch.Dockerfile .
