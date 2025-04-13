# SECURITY ADVISORY: LOC-2025-04

## Summary

A security concern has been identified in the Loco OAuth2 documentation where example code for user accounts created via OAuth2 authentication used the OAuth2 subject identifier (`sub` field) as a password hash input. This example, if followed, could potentially expose users to security risks.

## Severity

Medium

## Affected Documentation Versions

All documentation versions prior to 0.4.0

## Vulnerability Details

### Description

The documentation examples for OAuth2 user creation in previous versions of loco-oauth2 suggested using the OAuth2 provider's `sub` field (subject identifier) as input for password hashing during user creation. This practice, if implemented as shown in the examples, is problematic for several reasons:

1. The `sub` field is a persistent identifier that could potentially be exposed in logs or debugging information
2. OAuth2 subject identifiers are not designed for use as secret credentials
3. Implementing the example as shown creates a false sense of security while potentially exposing users to credential-based attacks

### Technical Impact

If developers implemented the example as shown and an attacker gains knowledge of a user's OAuth2 subject identifier, they could potentially:

-   Calculate the same password hash
-   Bypass authentication if the system allows direct password-based authentication alongside OAuth2

## Remediation

The documentation has been updated with secure example code that implements random password generation for OAuth2-created accounts. We recommend all users review their implementations if they followed the previous documentation examples and update according to the latest documentation for loco-oauth2.

### Old Documentation Example (Insecure)

```rust
// src/models/users.rs
use loco_oauth2::models::users::OAuth2UserTrait;
use loco_rs::{auth::jwt, hash, prelude::*};
use super::o_auth2_sessions;
use async_trait::async_trait;
use chrono::offset::Local;

#[async_trait]
impl OAuth2UserTrait<OAuth2UserProfile> for Model {
 async fn upsert_with_oauth(
        db: &DatabaseConnection,
        profile: &OAuth2UserProfile,
    ) -> ModelResult<Self> {
        // Start database transaction
        // Find user by email
        {
            None => {
                // We use the sub field as the user fake password since sub is unique
                let password_hash =
                    hash::hash_password(&profile.sub).map_err(|e| ModelError::Any(e.into()))?;
                // Create the user into the database
            }
            // Do nothing if user exists
        };
        // Commit database transaction
        Ok(user)
    }
}
```

### New Documentation Example (Secure)

Add to your `Cargo.toml`:

```toml
# Cargo.toml
[dependencies]
passwords = "3"
```

Update your implementation:

```rust
use passwords::PasswordGenerator;

#[async_trait]
impl OAuth2UserTrait<OAuth2UserProfile> for Model {
    async fn upsert_with_oauth(
        db: &DatabaseConnection,
        profile: &OAuth2UserProfile,
    ) -> ModelResult<Self> {
        let txn = db.begin().await?;
        let user = match users::Entity::find()
            .filter(users::Column::Email.eq(&profile.email))
            .one(&txn)
            .await?
        {
            None => {
                let pg = PasswordGenerator::new()
                    .length(16)  // Increased from 8 for better security
                    .numbers(true)
                    .lowercase_letters(true)
                    .uppercase_letters(true)
                    .symbols(true)
                    .exclude_similar_characters(true)
                    .strict(true);
                let password = pg.generate_one().map_err(|e| ModelError::Any(e.into()))?;

                // Optional: Send the generated password to user's email for initial login

                let password_hash =
                    hash::hash_password(&password).map_err(|e| ModelError::Any(e.into()))?;

                users::ActiveModel {
                    email: ActiveValue::set(profile.email.to_string()),
                    name: ActiveValue::set(profile.name.to_string()),
                    email_verified_at: ActiveValue::set(Some(Local::now().into())),
                    password: ActiveValue::set(password_hash),
                    ..Default::default()
                }
                .insert(&txn)
                .await
                .map_err(|e| {
                    tracing::error!("Error while trying to create user: {e}");
                    ModelError::Any(e.into())
                })?
            }
            // Do nothing if user exists
            Some(user) => user,
        };
        txn.commit().await?;
        Ok(user)
    }
}
```

## Timeline

-   **2025-04-13**: Documentation security issue identified during review
-   **2025-04-13**: Documentation updated in version 0.4.0
-   **2025-04-13**: Security advisory published

## Acknowledgements

This documentation issue was identified during an internal review of the loco-oauth2 documentation examples.

## References

-   [OWASP Authentication Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
-   [OAuth 2.0 Security Best Practices](https://oauth.net/2/oauth-best-practice/)
