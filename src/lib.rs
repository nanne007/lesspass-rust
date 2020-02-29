use pbkdf2;
use uint::construct_uint;

construct_uint! {
    pub struct U256(4);
}

pub struct PasswordProfile {
    pub site: String,
    pub login: String,
    pub max_len: u8,
    pub counter: u64,
    pub char_rule: CharRule,
}

#[derive(Debug, Hash, Copy, Clone)]
pub struct CharRule(pub u8);
impl Default for CharRule {
    fn default() -> Self {
        Self(0b00001111)
    }
}

impl CharRule {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn not_use_lowercase(&self) -> Self {
        Self(self.0 ^ (1 << 0))
    }
    pub fn not_use_uppercase(&self) -> Self {
        Self(self.0 ^ (1 << 1))
    }
    pub fn not_use_digits(&self) -> Self {
        Self(self.0 ^ (1 << 2))
    }
    pub fn not_use_symbols(&self) -> Self {
        Self(self.0 ^ (1 << 3))
    }
}

const LOWERCASE_CHARS: &'static str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE_CHARS: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &'static str = "0123456789";
const SYMBOLS: &'static str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const PASSWORD_CHARS: [&'static str; 4] = [LOWERCASE_CHARS, UPPERCASE_CHARS, DIGITS, SYMBOLS];

pub fn generate_password(password_profile: PasswordProfile, master_password: String) -> String {
    let entropy = calc_entropy(&password_profile, master_password.as_bytes());
    derive_password(
        entropy,
        password_profile.char_rule.0,
        password_profile.max_len,
    )
}

fn calc_entropy(password_profile: &PasswordProfile, master_password: &[u8]) -> U256 {
    let salt = format!(
        "{}{}{:x}",
        &password_profile.site, &password_profile.login, password_profile.counter
    );
    // 256-bit derived key
    let mut dk = [0u8; 32];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(master_password, salt.as_bytes(), 100000, &mut dk);
    dk.into()
}

fn derive_password(mut entropy: U256, rule: u8, max_len: u8) -> String {
    assert!(max_len >= 4);
    let candidate_chars = {
        let mut candidate_chars = vec![];
        for i in 0..4u8 {
            if (rule & (1 << i)) != 0 {
                candidate_chars.extend_from_slice(PASSWORD_CHARS[i as usize].as_bytes());
            }
        }
        candidate_chars
    };
    let candidate_len = candidate_chars.len();
    let mut generated_password = vec![];
    generated_password.truncate(max_len as usize);
    // First, random select char from all candidate chars.
    // wont overflow here.
    let mut random_gen_len = max_len - rule.count_ones() as u8;
    while random_gen_len > 0 {
        let (quotient, remainder) = entropy.div_mod(candidate_len.into());
        generated_password.push(candidate_chars[remainder.as_usize()]);
        random_gen_len -= 1;
        entropy = quotient;
    }
    // Then, select one char from each rule list.
    let mut one_char_per_rule = vec![];
    for i in 0..4u8 {
        if (rule & (1 << i)) != 0 {
            let rule = PASSWORD_CHARS[i as usize].as_bytes();
            let (quotient, remainder) = entropy.div_mod(rule.len().into());
            one_char_per_rule.push(rule[remainder.as_usize()]);
            entropy = quotient;
        }
    }

    // And then, insert them into random generated chars.
    for char in one_char_per_rule.into_iter() {
        let (quotient, remainder) = entropy.div_mod(generated_password.len().into());
        entropy = quotient;
        generated_password.insert(remainder.as_usize(), char);
    }
    unsafe { String::from_utf8_unchecked(generated_password) }
}

#[test]
pub fn test_all_letter() {
    let char_rule = CharRule::default();
    let site = "example.org".to_string();
    let login = "contact@example.org".to_string();

    let cases = vec![
        (site.clone(), login.clone(), 16, 1, char_rule),
        (
            site.clone(),
            login.clone(),
            14,
            2,
            char_rule.not_use_symbols(),
        ),
        (
            site.clone(),
            login.clone(),
            16,
            1,
            char_rule
                .not_use_lowercase()
                .not_use_uppercase()
                .not_use_symbols(),
        ),
        (
            site.clone(),
            login.clone(),
            16,
            1,
            char_rule.not_use_digits(),
        ),
    ];
    let expected = vec![
        "WHLpUL)e00[iHR+w",
        "MBAsB7b1Prt8Sl",
        "8742368585200667",
        "s>{F}RwkN/-fmM.X",
    ];

    let master_pass = "password";
    for (i, c) in cases.into_iter().enumerate() {
        let (site, login, max_len, counter, char_rule) = c;
        let profile = PasswordProfile {
            site,
            login,
            max_len,
            counter,
            char_rule,
        };
        let pass = generate_password(profile, master_pass.to_string());
        assert_eq!(&pass, expected[i]);
    }
}
