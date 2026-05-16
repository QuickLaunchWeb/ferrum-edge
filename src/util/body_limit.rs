//! Helpers for request-body size limit errors.

use http_body_util::LengthLimitError;

pub fn is_length_limit_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(err) = current {
        if err.downcast_ref::<LengthLimitError>().is_some() {
            return true;
        }
        current = err.source();
    }
    false
}
