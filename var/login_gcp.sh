#!/usr/bin/env bash
apt-get update && \
apt-get install -y lsb-release curl gnupg && \
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - && \
apt-get update && apt-get -y install google-cloud-sdk && \
echo "$GOOGLE_APPLICATION_CREDENTIALS" > "/root/key.json" && \
gcloud auth activate-service-account --key-file=/root/key.json