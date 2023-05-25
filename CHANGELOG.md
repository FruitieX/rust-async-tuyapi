# Changelog

## [1.0.0](https://github.com/FruitieX/rust-async-tuyapi/compare/v0.8.0...v1.0.0) (2023-05-25)


### ⚠ BREAKING CHANGES

* the `TuyaDevice` methods no longer return data from the device. Instead, `TuyaDevice::connect` returns a channel that you can read incoming messages from.

### Code Refactoring

* tuya tcp read task ([3ef8df9](https://github.com/FruitieX/rust-async-tuyapi/commit/3ef8df99bce0e1f9471fc4e02077b4da18a053ce))
