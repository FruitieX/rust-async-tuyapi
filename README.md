# rust-async-tuyapi
Rust async implementation of the Tuya API used to communicate with Tuya/Smart Life devices.

This crate supports musl targets.

Original sync version here: https://github.com/EmilSodergren/rust-tuyapi

## Acknowledgment
- @codetheweb for reverse enginering the protocol.
- The [https://pypi.org/project/tinytuya/](tinytuya) project for v3.4 protocol implementation

## Prerequisites
You need to know the key and id of the Tuya device. According to me the easiest way to find these is explained at: [Step by Step for adding Tuya-bulbs](https://community.openhab.org/t/step-by-step-guide-for-adding-tuya-bulbs-wi-fi-smart-led-smart-life-app-to-oh2-using-tuya-mqtt-js-by-agentk/59371)
