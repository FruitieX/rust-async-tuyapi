# Changelog

## [1.0.1](https://github.com/FruitieX/rust-async-tuyapi/compare/v1.0.0...v1.0.1) (2023-07-19)


### Bug Fixes

* **deps:** update rust crate aes to 0.8.3 ([0ef41df](https://github.com/FruitieX/rust-async-tuyapi/commit/0ef41df29982310fc7a6b0334717c7d3fc992941))
* **deps:** update rust crate ecb to 0.1.2 ([9479a38](https://github.com/FruitieX/rust-async-tuyapi/commit/9479a38c8ca872d79bae1033cf059f71d53bc022))
* **deps:** update rust crate num-derive to 0.4 ([462eb16](https://github.com/FruitieX/rust-async-tuyapi/commit/462eb1697d132692ebc5e5dddd10c483a3b8c9fe))
* **deps:** update rust crate sha2 to 0.10.7 ([5bced2d](https://github.com/FruitieX/rust-async-tuyapi/commit/5bced2d4c6adf62a995c5f6b3c4e42634a81fa77))

## [1.0.0](https://github.com/FruitieX/rust-async-tuyapi/compare/v0.8.0...v1.0.0) (2023-05-25)


### ⚠ BREAKING CHANGES

* the `TuyaDevice` methods no longer return data from the device. Instead, `TuyaDevice::connect` returns a channel that you can read incoming messages from.

### Code Refactoring

* tuya tcp read task ([3ef8df9](https://github.com/FruitieX/rust-async-tuyapi/commit/3ef8df99bce0e1f9471fc4e02077b4da18a053ce))
