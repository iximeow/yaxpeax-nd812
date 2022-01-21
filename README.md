## yaxpeax-nd812  

[![crate](https://img.shields.io/crates/v/yaxpeax-nd812.svg?logo=rust)](https://crates.io/crates/yaxpeax-nd812)
[![documentation](https://docs.rs/yaxpeax-nd812/badge.svg)](https://docs.rs/yaxpeax-nd812)

an `ND812` decoder implemented as part of the yaxpeax project, including traits provided by [`yaxpeax-arch`](https://git.iximeow.net/yaxpeax-arch/about/).

the `ND812` is a 12-bit microcomputer intended for scientific computing purposes, from Nuclear Data, Inc. several other related systems, such as the `ND4410`, require an `ND812` microcomputer for operation - some program listings to operate those additional pieces of hardware are executed on the attached `ND812`. the `ND812` itself was first sold in 1970.

users of this library will either want to use [quick and dirty APIs](https://docs.rs/yaxpeax-nd812/latest/yaxpeax_nd812/index.html#usage), or more generic decode interfaces from `yaxpeax-arch` - appropriate when mixing `yaxpeax-nd812` with other `yaxpeax` decoders, such as `yaxpeax-x86`.

### features

* it exists
* `#[no_std]`

### it exists

there aren't many ND812 programs, and fewer ND812 simulators. presumably, someone wanting to simulate an ND812 would need to interpret its instructions. all ND812 programs i've found are text listings and an interpreter could easily be written to interpret the 12-bit-octal-words-as-text directly.. but, well, a binary decoder exists now.

### `#[no_std]`

if, for some reason, you want to disassemble `ND812` instructions without the Rust standard library around, that should work. this is primarily for consistency with other decoders than any need, and is not particularly tested.
