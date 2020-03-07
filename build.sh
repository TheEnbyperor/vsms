#!/usr/bin/env bash

VERSION=$(sentry-cli releases propose-version || exit)

docker build -t "theenbyperor/wwfypc-vsms:$VERSION" . || exit
docker push "theenbyperor/wwfypc-vsms:$VERSION" || exit
