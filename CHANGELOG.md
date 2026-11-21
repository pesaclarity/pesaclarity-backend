# Changelog

All notable changes to the server are listed here. Versions follow [semantic versioning](https://semver.org); until 1.0 a minor version may change the API.

## [0.2.0](https://github.com/pesaclarity/pesaclarity-backend/compare/v0.1.0...v0.2.0) (2026-11-21)


### Features

* add signed app status and admin notices ([#51](https://github.com/pesaclarity/pesaclarity-backend/issues/51)) ([1451f9a](https://github.com/pesaclarity/pesaclarity-backend/commit/1451f9ae428a559599aadb7d775b5340b011d0a5))
* **admin:** overview fixes and the wider layout, with a downloads page ([c2a97e2](https://github.com/pesaclarity/pesaclarity-backend/commit/c2a97e2130adf9456fa9bba755a99fe50f505b57))
* Apple App Attest for vault uploads from iPhone ([0342bbc](https://github.com/pesaclarity/pesaclarity-backend/commit/0342bbc5694bf8c02c53342ef4a66429519d4fe7))
* Apple App Attest for vault uploads from iPhone ([#27](https://github.com/pesaclarity/pesaclarity-backend/issues/27)) ([7c4c244](https://github.com/pesaclarity/pesaclarity-backend/commit/7c4c24452484c4412667ceaa188bac184685e815))
* count installs, take crash reports and add the passkey dashboard ([da77221](https://github.com/pesaclarity/pesaclarity-backend/commit/da772213a366fe8cf9750c53a29887fdd1225372))
* email a copy of the privacy policy ([#40](https://github.com/pesaclarity/pesaclarity-backend/issues/40)) ([ff1fe5a](https://github.com/pesaclarity/pesaclarity-backend/commit/ff1fe5ab2909d67e6b4f94514647ed04f6ca50e9))
* keep backups per space ([#38](https://github.com/pesaclarity/pesaclarity-backend/issues/38)) ([7c629e4](https://github.com/pesaclarity/pesaclarity-backend/commit/7c629e4b2eb3b811486a0d66e4cf01e96d38d06f))
* migrate the database as each revision starts ([#45](https://github.com/pesaclarity/pesaclarity-backend/issues/45)) ([31d893f](https://github.com/pesaclarity/pesaclarity-backend/commit/31d893fde2b783cfc0143c8a5120767702f14f64))
* open the admin dashboard on more than one origin ([b467660](https://github.com/pesaclarity/pesaclarity-backend/commit/b467660eb87c54cc46cdc592f164b3ad9728bfce))
* open the admin dashboard on more than one origin ([bdc3e7e](https://github.com/pesaclarity/pesaclarity-backend/commit/bdc3e7e1f47b0adbff132c2c76dda1a6973fec58))
* redesign the admin dashboard with trends, filters and marked suppression ([eaffa8d](https://github.com/pesaclarity/pesaclarity-backend/commit/eaffa8d96c0296ee4f83d486ae80a5f1e44a3df8))
* redesign the admin dashboard with trends, filters and marked suppression ([efcfd09](https://github.com/pesaclarity/pesaclarity-backend/commit/efcfd09a6dc0c50653161618c8ec8a363703e3ed))
* sign in to the admin dashboard with a password and a second factor ([1013535](https://github.com/pesaclarity/pesaclarity-backend/commit/1013535811dd71c7ee30617afc10a2b9ec7b7e9c))


### Fixes

* **admin:** centre the sign-in page on wide screens ([f1cdee5](https://github.com/pesaclarity/pesaclarity-backend/commit/f1cdee5e27d4d499108f91d8cc824250e2fa8bfa))
* **admin:** centre the sign-in pages on wide screens ([82e0ed3](https://github.com/pesaclarity/pesaclarity-backend/commit/82e0ed344e1b4a6ed60b2d1ce8afd5fc85165efa))
* **admin:** name Pesa Clarity as two words in the password rules ([3bac00e](https://github.com/pesaclarity/pesaclarity-backend/commit/3bac00e342951c8fc58f36c2153e429e0451b8e3))
* install on Intel Macs, keep the Build menu on screen, and give the admin a favicon ([f130bfb](https://github.com/pesaclarity/pesaclarity-backend/commit/f130bfb7719cae3261878f1bb38ce44a2370497e))
* set the policy digest with the server settings ([#42](https://github.com/pesaclarity/pesaclarity-backend/issues/42)) ([e6f2c61](https://github.com/pesaclarity/pesaclarity-backend/commit/e6f2c618ed6b9bf27b5e4e8eb43e670f3e55870f))
* take the caller's country from the address Google appends, not one the caller wrote ([4bdd265](https://github.com/pesaclarity/pesaclarity-backend/commit/4bdd265fd232f93596d962d5f4790d82aad4dcb8))

## 0.1.0

First version: phone sign-in, the zero-knowledge backup vault with retention and purge, Play Integrity checks on uploads, federated-learning aggregation, and deployment to Cloud Run.
