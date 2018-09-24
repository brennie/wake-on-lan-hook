# wake-on-lan-hook

[![CircleCI Build Status][circle-ci-img]][circle-ci]
[![Documentation][docs-img]][docs]

---

`wake-on-lan-hook` is a tool for triggering commands when a
[wake-on-LAN][wiki] is received. This is useful, for example, if you wish to
us wake-on-LAN packets to start virtual machines, which typically cannot listen
for the packets themselves.

Presently, `wake-on-lan-hook` only supports UDP packets and not raw Ethernet
packets. For more details, see the [documentation][docs].

Example usage:

- A [systemd unit file][ex-systemd-unit] that launches a VM when a wake-on-LAN packet is received.


[circle-ci]: https://circleci.com/gh/brennie/workflows/wake-on-lan-hook
[circle-ci-img]: https://img.shields.io/circleci/project/github/brennie/wake-on-lan-hook.svg?style=flat-square&logo=circleci
[docs]: https://brennie.github.io/wake-on-lan-hook
[docs-img]: https://img.shields.io/circleci/project/github/brennie/wake-on-lan-hook.svg?style=flat-square&label=docs
[ex-systemd-unit]: https://github.com/brennie/wake-on-lan-hook/blob/master/contrib/wake-on-lan-hook.service
[wiki]: https://en.wikipedia.org/wiki/Wake-on-LAN
