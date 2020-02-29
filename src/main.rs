use clap::Clap;
use lesspass::{generate_password, CharRule, PasswordProfile};

fn main() {
    let opts: Opts = Opts::parse();
    match opts.sub_cmd {
        SubCommand::GenPassword(mut gen_pass) => {
            let master_password = match gen_pass.master_password.take() {
                None => rpassword::prompt_password_stdout("master password: ").unwrap(),
                Some(p) => p,
            };
            let GenPassword {
                site,
                login,
                length,
                counter,
                no_uppercase,
                no_lowercase,
                no_digits,
                no_symbols,
                ..
            } = gen_pass;
            let mut char_rule = CharRule::default();
            if no_lowercase {
                char_rule = char_rule.not_use_lowercase();
            }
            if no_uppercase {
                char_rule = char_rule.not_use_uppercase();
            }
            if no_digits {
                char_rule = char_rule.not_use_digits();
            }
            if no_symbols {
                char_rule = char_rule.not_use_symbols();
            }

            let profile = PasswordProfile {
                site,
                login,
                max_len: length,
                counter,
                char_rule,
            };
            let generated_pass = generate_password(profile, master_password);
            println!("{}", generated_pass);
        }
    }
}

#[derive(Clap, Debug)]
#[clap(
    version = "1.0.0",
    author = "nonsense <nonsense0202@pm.me>",
    about = "lesspass tools"
)]
struct Opts {
    #[clap(subcommand)]
    sub_cmd: SubCommand,
}

#[derive(Clap, Debug)]
enum SubCommand {
    #[clap(name = "gen")]
    GenPassword(GenPassword),
}

#[derive(Clap, Debug)]
struct GenPassword {
    #[clap(
        long = "site",
        short = "s",
        required = true,
        help = "site used in the password generation"
    )]
    site: String,

    #[clap(
        long = "login",
        short = "l",
        required = true,
        help = "login used in the password generation"
    )]
    login: String,

    #[clap(
        short = "L",
        long = "length",
        default_value = "16",
        help = "password length"
    )]
    length: u8,

    #[clap(
        short = "C",
        long = "counter",
        default_value = "1",
        help = "password counter"
    )]
    counter: u64,

    #[clap(long = "no-lowercase", help = "do not use lowercase letter")]
    no_lowercase: bool,

    #[clap(long = "no-uppercase", help = "do not use uppercase letter")]
    no_uppercase: bool,

    #[clap(long = "no-digits", help = "do not use digits letter")]
    no_digits: bool,

    #[clap(long = "no-symbols", help = "do not use symbol letter")]
    no_symbols: bool,

    #[clap(
        short = "p",
        long = "password",
        help = "master password used in password generation, or else prompt from tty"
    )]
    master_password: Option<String>,
}
