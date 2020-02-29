# lesspass-rust

Lesspass is a tool to derive password to login in websites, apps based on one true master password. 
See https://lesspass.com/ for more detail.

And this is a CLI implemented in Rust to generate lesspass password.

## Usage

``` shell
# install with cargo
> cargo install lesspass
> lesspass help
> lesspass gen --help
```

Generate a 20-length password for site *www.facebook.com* using login *lesspass@example.com*.
``` shell
lesspass gen --site www.facebook.com --login lesspass@example.com --length 20 
```
This will prompt you to input your master password.