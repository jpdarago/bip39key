//! Fixed-width line wrapping for base64 blocks.

/// Split `text` into lines of exactly `width` characters, except the last,
/// which holds the remainder. Lines are joined with `\n`, with no trailing
/// newline.
///
/// OpenSSH writes private keys this way (70 columns) and GnuPG writes armor
/// this way (64 columns). bip39key used `textwrap::fill`, which breaks at word
/// boundaries and treats `/` as one, so lines came out uneven. ssh-keygen and
/// GnuPG tolerate that, but strict RFC 7468 parsers reject it.
///
/// `text` must be ASCII, which base64 always is.
pub fn fixed_width(text: &str, width: usize) -> String {
    assert!(width > 0, "line width must be positive");
    assert!(text.is_ascii(), "only ASCII text can be split by byte");
    text.as_bytes()
        .chunks(width)
        // Each chunk is ASCII, so it is valid UTF-8.
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn empty_input_is_empty() {
        assert_eq!(fixed_width("", 64), "");
    }

    #[test]
    fn breaks_at_slash_only_at_the_width() {
        // textwrap::fill would break after the '/'.
        assert_eq!(fixed_width("ab/cdef", 4), "ab/c\ndef");
    }

    proptest! {
        #[test]
        fn lines_are_full_width_except_the_last(
            text in "[A-Za-z0-9+/=]{0,600}",
            width in 1usize..100,
        ) {
            let wrapped = fixed_width(&text, width);
            let lines: Vec<&str> = if text.is_empty() {
                vec![]
            } else {
                wrapped.split('\n').collect()
            };
            prop_assert_eq!(lines.concat(), text.clone());
            if let Some((last, full)) = lines.split_last() {
                prop_assert!(full.iter().all(|line| line.len() == width));
                prop_assert!(!last.is_empty() && last.len() <= width);
            }
        }
    }
}
