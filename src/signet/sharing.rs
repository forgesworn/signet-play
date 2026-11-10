//! Explicit public result sharing, separate from private play permissions.
use super::*;
use nostr::UnsignedEvent;

pub(crate) const PROFILE_SESSION: &str = "public-profile-session.json";
pub(crate) const NOTE_SESSION: &str = "public-note-session.json";
pub(crate) const SCORE_SESSION: &str = "public-score-session.json";
const STATUS_METHOD: &str = "signet_get_public_profile";
const REAUTHORISE: &str = "Approve this connection again in My Signet.";
const UNSUPPORTED: &str = "Update My Signet to check this profile.";
const READ_TIMEOUT: Duration = Duration::from_secs(15);

async fn read_request<T>(
    request: impl std::future::Future<Output = Result<T, nip46::Error>>,
    step: &str,
) -> Result<T, String> {
    match tokio::time::timeout(READ_TIMEOUT, request).await {
        Err(_) | Ok(Err(nip46::Error::Timeout)) => Err(format!(
            "My Signet didn't answer while {step}. Unlock it and try again."
        )),
        Ok(result) => result.map_err(sharing_failure),
    }
}

fn sharing_failure(error: nip46::Error) -> String {
    if let nip46::Error::Signer(code) = &error {
        let message = match code.as_str() {
            "permission not granted" | "approve requested permissions with nostrconnect" => {
                REAUTHORISE
            }
            "unsupported" | "method not supported" => UNSUPPORTED,
            "public profile required" => "This My Signet profile is private.",
            "public profile unsupported" => "My Signet cannot confirm this profile yet.",
            "public profile unknown" | "public profile unavailable" | "public profile stale" => {
                "My Signet could not confirm this profile. Try again."
            }
            "persona changed" => "Your My Signet profile changed.",
            "user denied" | "denied" => "You declined in My Signet.",
            _ => "My Signet could not approve this request. Try again.",
        };
        return message.into();
    }
    friendly(error)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SharingScope {
    Profile,
    Note,
    Score,
}

impl SharingScope {
    pub fn permission(self) -> &'static str {
        match self {
            Self::Profile => STATUS_METHOD,
            Self::Note => "sign_event:1:public_profile",
            Self::Score => "sign_event:30762:public_profile",
        }
    }
    fn file(self) -> &'static str {
        match self {
            Self::Profile => PROFILE_SESSION,
            Self::Note => NOTE_SESSION,
            Self::Score => SCORE_SESSION,
        }
    }
    fn kind(self) -> Option<u16> {
        match self {
            Self::Profile => None,
            Self::Note => Some(1),
            Self::Score => Some(30762),
        }
    }
}

/// Valid only in the sign-in session whose authenticated query produced it.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicProfileStatus {
    pub v: u8,
    pub request_id: String,
    pub client_pubkey: String,
    pub persona_pubkey: String,
    pub enabled: bool,
    pub checked_at: u64,
    pub expires_at: u64,
    pub conditional_scopes: Vec<String>,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl PublicProfileStatus {
    pub fn is_public_at(&self, persona: &PublicKey, now: u64) -> bool {
        self.v == 1
            && self.enabled
            && self.persona_pubkey == persona.to_hex()
            && self.checked_at <= now
            && self.expires_at == self.checked_at.saturating_add(5000)
            && now < self.expires_at
    }
    pub fn supports(&self, scope: SharingScope) -> bool {
        scope != SharingScope::Profile
            && self
                .conditional_scopes
                .iter()
                .any(|p| p == scope.permission())
    }
    fn validate(
        &self,
        signer: &RemoteSigner,
        persona: &PublicKey,
        request: &str,
        now: u64,
    ) -> Result<(), String> {
        if self.v != 1
            || self.request_id != request
            || self.client_pubkey != signer.client_public_key().to_hex()
            || self.persona_pubkey != persona.to_hex()
        {
            return Err("My Signet answered for a different profile or request.".into());
        }
        if self.checked_at > now
            || self.expires_at != self.checked_at.saturating_add(5000)
            || now >= self.expires_at
        {
            return Err("My Signet's profile status has expired.".into());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct ApprovedConnection {
    scope: SharingScope,
    session: PersistedSession,
}

pub enum SharingApprovalEvent {
    OpenSigner(String),
    Connected,
    Approved(PublicProfileStatus),
    Failed(String),
}

/// Dropping a pending approval closes it without installing its connection.
pub struct SharingApproval {
    rx: mpsc::Receiver<SharingApprovalEvent>,
    abort: AbortHandle,
}
impl SharingApproval {
    pub fn poll(&self) -> Option<SharingApprovalEvent> {
        self.rx.try_recv().ok()
    }
}
impl Drop for SharingApproval {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

async fn status(signer: &RemoteSigner, persona: &PublicKey) -> Result<PublicProfileStatus, String> {
    let id = nip46::generate_connect_secret();
    // Status needs no human signing decision. Do not hold the UI for the
    // longer timeout reserved for an actual signature approval.
    let raw = read_request(
        signer.request_with_id(&id, STATUS_METHOD, vec![persona.to_hex()]),
        "checking profile status",
    )
    .await?;
    let status: PublicProfileStatus = serde_json::from_str(&raw)
        .map_err(|_| "My Signet returned an invalid profile status.".to_string())?;
    status.validate(signer, persona, &id, now_ms())?;
    Ok(status)
}

fn current(inner: &Inner, persona: PublicKey, generation: u64) -> bool {
    let st = inner.lock();
    !st.retired && st.persona == Some(persona) && st.sign_in_gen == generation
}

fn session(inner: &Inner, scope: SharingScope, persona: &PublicKey) -> Option<PersistedSession> {
    inner
        .store
        .load::<ApprovedConnection>(scope.file())
        .filter(|s| s.scope == scope && s.session.persona == persona.to_hex())
        .map(|s| s.session)
}

fn forget_revoked(inner: &Inner, scope: SharingScope, saved: &PersistedSession, reason: &str) {
    if reason != REAUTHORISE && reason != UNSUPPORTED {
        return;
    }
    let mut st = inner.lock();
    if st
        .persona
        .is_some_and(|p| session(inner, scope, &p).as_ref() == Some(saved))
    {
        inner.store.remove(scope.file());
        st.sharing_signers.remove(&scope);
    }
}

async fn scoped_status(
    inner: &Inner,
    scope: SharingScope,
    saved: &PersistedSession,
    signer: &RemoteSigner,
    persona: &PublicKey,
) -> Result<PublicProfileStatus, String> {
    let result = status(signer, persona).await;
    if let Err(reason) = &result {
        forget_revoked(inner, scope, saved, reason);
    }
    result
}

async fn connection(
    inner: &Arc<Inner>,
    scope: SharingScope,
    saved: &PersistedSession,
) -> Result<Arc<RemoteSigner>, String> {
    if let Some((_, signer)) = inner
        .lock()
        .sharing_signers
        .get(&scope)
        .filter(|(s, _)| s == saved)
    {
        return Ok(signer.clone());
    }
    let relay = inner.connector.connect(&saved.relays);
    let signer =
        RemoteSigner::restore(saved, relay, inner.cfg.request_timeout).map_err(sharing_failure)?;
    if let Err(reason) = read_request(signer.connect(), "restoring the approved connection").await {
        forget_revoked(inner, scope, saved, &reason);
        return Err(reason);
    }
    let signer = Arc::new(signer);
    let mut st = inner.lock();
    if st.retired || st.persona.map(|p| p.to_hex()).as_ref() != Some(&saved.persona) {
        return Err("Your My Signet profile changed.".into());
    }
    st.sharing_signers
        .insert(scope, (saved.clone(), signer.clone()));
    Ok(signer)
}

impl Signet {
    /// No network traffic: whether this persona explicitly connected profile status.
    pub fn has_public_profile_connection(&self) -> bool {
        self.persona()
            .is_some_and(|p| session(&self.inner, SharingScope::Profile, &p).is_some())
    }

    pub fn has_sharing_permission(&self, scope: SharingScope) -> bool {
        self.persona()
            .is_some_and(|p| session(&self.inner, scope, &p).is_some())
    }

    /// A read-only, authenticated check. Never substitutes an old relay profile.
    pub fn public_profile_status(&self) -> Task<Result<PublicProfileStatus, String>> {
        let inner = self.inner.clone();
        let (persona, generation) = {
            let st = inner.lock();
            (st.persona, st.sign_in_gen)
        };
        Task::spawn(async move {
            let persona = persona.ok_or("Sign in to My Signet first.")?;
            let saved = session(&inner, SharingScope::Profile, &persona)
                .ok_or("Connect profile status in Settings first.")?;
            let signer = connection(&inner, SharingScope::Profile, &saved).await?;
            let value =
                scoped_status(&inner, SharingScope::Profile, &saved, &signer, &persona).await?;
            if !current(&inner, persona, generation)
                || session(&inner, SharingScope::Profile, &persona).as_ref() != Some(&saved)
            {
                return Err("Your My Signet profile changed.".into());
            }
            Ok(value)
        })
    }

    /// A separate connection: read-only discovery, or one explicitly chosen posting kind.
    /// It never changes the game connection, runtime key, or its signing ceiling.
    pub fn approve_result_sharing(&self, scope: SharingScope) -> SharingApproval {
        let (tx, rx) = mpsc::channel();
        let inner = self.inner.clone();
        let (persona, generation) = {
            let st = inner.lock();
            (st.persona, st.sign_in_gen)
        };
        let job = runtime().spawn(async move {
            let outcome = async {
                let persona = persona.ok_or("Sign in to My Signet first.")?;
                if !current(&inner, persona, generation) {
                    return Err("Your My Signet profile changed.".into());
                }
                if scope != SharingScope::Profile {
                    let saved = session(&inner, SharingScope::Profile, &persona)
                        .ok_or("Connect profile status in Settings first.")?;
                    let profile = connection(&inner, SharingScope::Profile, &saved).await?;
                    let fresh =
                        scoped_status(&inner, SharingScope::Profile, &saved, &profile, &persona)
                            .await?;
                    if !fresh.is_public_at(&persona, now_ms())
                        || !fresh.supports(scope)
                        || !current(&inner, persona, generation)
                    {
                        return Err("This profile cannot share public results.".into());
                    }
                }
                let permissions = if scope == SharingScope::Profile {
                    STATUS_METHOD.to_string()
                } else {
                    format!("{STATUS_METHOD},{}", scope.permission())
                };
                let relay = inner.connector.connect(&inner.cfg.relays);
                let (uri, pending) = PendingPair::start(relay, &inner.cfg.app_name, &permissions)
                    .map_err(friendly)?;
                let notify = tx.clone();
                let mut signer = pending
                    .await_signer(inner.cfg.pairing_timeout, move || {
                        let _ = notify.send(SharingApprovalEvent::OpenSigner(uri));
                    })
                    .await
                    .map_err(|error| {
                        if matches!(error, nip46::Error::Timeout) {
                            "No approval received from My Signet. If no request appeared, update My Signet, then try again.".into()
                        } else {
                            friendly(error)
                        }
                    })?;
                signer.set_timeout(inner.cfg.request_timeout);
                if !current(&inner, persona, generation) {
                    return Err("Your My Signet profile changed.".into());
                }
                let _ = tx.send(SharingApprovalEvent::Connected);
                log::info!("My Signet profile approval: connection approved");
                if read_request(signer.get_public_key(), "confirming your profile").await? != persona {
                    return Err("Choose the same My Signet profile you are playing as.".into());
                }
                let fresh = status(&signer, &persona).await?;
                log::info!("My Signet profile approval: authenticated status received");
                if scope != SharingScope::Profile
                    && (!fresh.is_public_at(&persona, now_ms()) || !fresh.supports(scope))
                {
                    return Err("This profile cannot share public results.".into());
                }
                // Hold the identity lock through the atomic save so sign-out cannot race it.
                let mut st = inner.lock();
                if st.retired || st.persona != Some(persona) || st.sign_in_gen != generation {
                    return Err("Your My Signet profile changed.".into());
                }
                let saved = signer.persist(&persona);
                inner
                    .store
                    .save(
                        scope.file(),
                        &ApprovedConnection {
                            scope,
                            session: saved.clone(),
                        },
                    )
                    .map_err(|e| e.to_string())?;
                // Keep the already verified transport instead of restoring another
                // socket and repeating connect immediately after returning to the app.
                st.sharing_signers.insert(scope, (saved, Arc::new(signer)));
                Ok::<_, String>(fresh)
            }
            .await;
            let _ = tx.send(match outcome {
                Ok(status) => SharingApprovalEvent::Approved(status),
                Err(e) => SharingApprovalEvent::Failed(e),
            });
        });
        SharingApproval {
            rx,
            abort: job.abort_handle(),
        }
    }

    /// Publish only a player-approved result, with a fresh public check on both sides
    /// of signing. Retry the same template to retain the event id after a lost ack.
    pub fn publish_public_result(
        &self,
        scope: SharingScope,
        unsigned: UnsignedEvent,
        destinations: Option<Vec<String>>,
    ) -> Task<Result<Event, String>> {
        let inner = self.inner.clone();
        let (persona, generation) = {
            let st = inner.lock();
            (st.persona, st.sign_in_gen)
        };
        Task::spawn(async move {
            let persona = persona.ok_or("Your My Signet profile changed.")?;
            if scope.kind() != Some(unsigned.kind.as_u16()) || unsigned.pubkey != persona {
                return Err("That result does not belong to this profile.".into());
            }
            let saved = session(&inner, scope, &persona)
                .ok_or("Approve result sharing in My Signet first.")?;
            let signer = connection(&inner, scope, &saved).await?;
            let check = async || {
                let s = scoped_status(&inner, scope, &saved, &signer, &persona).await?;
                if !current(&inner, persona, generation)
                    || session(&inner, scope, &persona).as_ref() != Some(&saved)
                {
                    return Err("Your My Signet profile or sharing permission changed.".to_string());
                }
                if !s.is_public_at(&persona, now_ms()) || !s.supports(scope) {
                    return Err("This profile cannot share public results.".into());
                }
                Ok(())
            };
            check().await?;
            let event = signer
                .sign_event(&unsigned, &persona)
                .await
                .map_err(|error| {
                    let reason = sharing_failure(error);
                    forget_revoked(&inner, scope, &saved, &reason);
                    reason
                })?;
            if event.created_at != unsigned.created_at {
                return Err("My Signet changed the result's date. Try again.".into());
            }
            check().await?;
            let relay = inner
                .connector
                .connect(destinations.as_deref().unwrap_or(&inner.cfg.relays));
            let report = relay
                .publish_acked(&event)
                .wait(inner.cfg.fetch_timeout)
                .await;
            if !report.succeeded() {
                return Err("No relay confirmed the post. Retry sends the same result.".into());
            }
            Ok(event)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_status_is_bound_to_identity_time_and_supported_scope() {
        let persona = Keys::generate().public_key();
        let mut value = PublicProfileStatus {
            v: 1,
            request_id: "id".into(),
            client_pubkey: "client".into(),
            persona_pubkey: persona.to_hex(),
            enabled: true,
            checked_at: 1000,
            expires_at: 6000,
            conditional_scopes: vec![SharingScope::Note.permission().into()],
        };
        assert!(value.is_public_at(&persona, 5999));
        assert!(!value.is_public_at(&persona, 6000));
        assert!(!value.is_public_at(&persona, 999));
        assert!(!value.is_public_at(&Keys::generate().public_key(), 2000));
        assert!(value.supports(SharingScope::Note));
        assert!(!value.supports(SharingScope::Score));
        value.enabled = false;
        assert!(!value.is_public_at(&persona, 2000));
        value.enabled = true;
        value.expires_at = 60_000;
        assert!(!value.is_public_at(&persona, 2000));
    }
}
