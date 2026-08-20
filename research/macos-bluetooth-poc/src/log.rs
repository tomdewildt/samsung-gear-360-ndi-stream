/// Print an indented detail line under the current top-level status.
macro_rules! step {
    ($($arg:tt)*) => { println!("  {}", format_args!($($arg)*)) };
}

pub(crate) use step;
