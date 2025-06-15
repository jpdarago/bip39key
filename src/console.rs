use std::io::{self, IsTerminal, Write};

pub fn is_output_interactive() -> bool {
    static IS_OUTPUT_INTERACTIVE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *IS_OUTPUT_INTERACTIVE.get_or_init(|| {
        let disabled = std::env::var("NO_INTERACTIVE_OUTPUT")
            .map(|v| v == "1")
            .unwrap_or(false);

        !disabled && io::stdout().is_terminal()
    })
}

pub fn is_input_interactive() -> bool {
    static IS_INPUT_INTERACTIVE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *IS_INPUT_INTERACTIVE.get_or_init(|| io::stdout().is_terminal())
}

pub fn flush() {
    io::stdout().flush().expect("Failed to flush stdout")
}

macro_rules! console_logln {
    ($($arg:tt)*) => {
        if $crate::console::is_output_interactive() {
            println!($($arg)*);
        }
    };
}

macro_rules! console_log {
    ($($arg:tt)*) => {
        if $crate::console::is_output_interactive() {
            print!($($arg)*);
            $crate::console::flush();
        }
    };
}
