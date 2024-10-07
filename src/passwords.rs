use rand::distributions::{Alphanumeric, Uniform};
use rand::{thread_rng, Rng};
use std::iter;
use unicode_segmentation::UnicodeSegmentation;

pub fn create_random_password(length: usize, allowed_chars: Option<String>) -> String {
    match allowed_chars {
        Some(chars) => create_password_with_allowed_chars(length, &chars),
        None => create_alphanumeric_password(length),
    }
}

fn create_alphanumeric_password(length: usize) -> String {
    let mut rng = thread_rng();

    iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(length)
        .collect()
}

fn create_password_with_allowed_chars(length: usize, allowed_chars: &str) -> String {
    let mut rng = thread_rng();

    let graphemes: Vec<&str> = allowed_chars.graphemes(true).collect();
    let uniform_between = Uniform::from(0..graphemes.len());

    iter::repeat(())
        .map(|()| rng.sample(uniform_between))
        .map(|nth| graphemes.get(nth).unwrap().to_owned())
        .take(length)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn create_alphanumeric_password__valid_length() {
        let password = create_alphanumeric_password(21);
        let password_graphemes: Vec<&str> = password.graphemes(true).collect();
        assert_eq!(password_graphemes.len(), 21);
    }

    #[test]
    #[allow(non_snake_case)]
    fn create_alphanumeric_password__valid_chars() {
        let allowed_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let password = create_password_with_allowed_chars(1000, allowed_chars);
        password
            .chars()
            .for_each(|c| assert!(allowed_chars.contains(c)));
    }

    #[test]
    #[allow(non_snake_case)]
    fn create_password_with_allowed_chars__valid_length() {
        let password = create_password_with_allowed_chars(21, "abcdनमस्ते्🏴‍☠️🦀");
        let password_graphemes: Vec<&str> = password.graphemes(true).collect();
        assert_eq!(password_graphemes.len(), 21);
    }

    #[test]
    #[allow(non_snake_case)]
    fn create_password_with_allowed_chars__valid_chars() {
        let allowed_chars = "abcd6291AZKJO%!$%*&äöüनमस्ते्🏴‍☠️🦀";
        let password = create_password_with_allowed_chars(1000, allowed_chars);
        password
            .chars()
            .for_each(|c| assert!(allowed_chars.contains(c)));
    }
}
