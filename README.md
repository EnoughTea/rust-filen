# Way to call Filen.io API from Rust

This is currently under development and **not in a usable state**.

[Filen.io](https://filen.io) is a cloud storage provider with an open-source desktop client. Naturally, this client is written in node.js and has questionable performance. My goal is to write altertative client, learning Rust in process.
First of the biggest hurdles, compatible crypto implementation, is done. Now to actually figure the way to properly call Filen API by studying [filen-desktop](https://github.com/FilenCloudDienste/filen-desktop)...