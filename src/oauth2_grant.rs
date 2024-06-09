use std::sync::Arc;

use tokio::sync::Mutex;

use crate::grants::authorization_code::GrantTrait;

#[derive(Clone)]
pub enum OAuth2ClientGrantEnum {
    AuthorizationCode(Arc<Mutex<dyn GrantTrait>>),
    ClientCredentials,
    DeviceCode,
    Implicit,
    ResourceOwnerPasswordCredentials,
}
