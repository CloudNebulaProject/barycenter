use crate::settings::Settings;
use axum::http::HeaderMap;

pub const SESSION_COOKIE_NAME: &str = "barycenter_session";

#[derive(Clone, Debug)]
pub struct SessionCookie {
    pub session_id: String,
}

impl SessionCookie {
    pub fn new(session_id: String) -> Self {
        Self { session_id }
    }

    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;

        // Parse cookie header for our session cookie
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some(value) = cookie.strip_prefix(SESSION_COOKIE_NAME).and_then(|s| s.strip_prefix('=')) {
                return Some(Self {
                    session_id: value.to_string(),
                });
            }
        }
        None
    }

    pub fn to_cookie_header(&self, settings: &Settings) -> String {
        let secure = settings.issuer().starts_with("https://");
        let max_age = 3600; // 1 hour default

        format!(
            "{}={}; HttpOnly; {}SameSite=Lax; Path=/; Max-Age={}",
            SESSION_COOKIE_NAME,
            self.session_id,
            if secure { "Secure; " } else { "" },
            max_age
        )
    }

    pub fn delete_cookie_header() -> String {
        format!(
            "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
            SESSION_COOKIE_NAME
        )
    }
}
