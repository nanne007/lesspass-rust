# lesspass-rust

Lesspass is a tool to derive password to login in websites, apps based on one true master password. 

See https://lesspass.com/ for more detail.

This is a CLI implemented in Rust to generate lesspass password, and it's compatible with [origin python&js implementation](https://github.com/lesspass/lesspass).


## Usage

``` shell
# install with cargo
> cargo install --git https://github.com/nonsense2020/lesspass-rust
> lesspass help
> lesspass gen --help
```

Generate a 20-length password for site *www.facebook.com* using login *lesspass@example.com*.
``` shell
lesspass gen --site www.facebook.com --login lesspass@example.com --length 20 
```
This will prompt you to input your master password.