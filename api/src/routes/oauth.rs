use oauth2::{AuthorizationCode, CsrfToken};
use serde::Deserialize;
use strum::{Display, EnumIs, EnumString};

pub mod github;

#[allow(dead_code)]
#[derive(Deserialize)]
struct OauthCallbackRequest {
    pub code: AuthorizationCode,
    pub state: CsrfToken,
    pub action: OauthCallbackAction,
}

#[derive(EnumString, EnumIs, Display, Deserialize)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
enum OauthCallbackAction {
    Authenticate,
    Register,
    Associate,
    Remove,
}

impl OauthCallbackAction {
    pub fn requires_authentication(&self) -> bool {
        self.is_associate() || self.is_remove()
    }
}
