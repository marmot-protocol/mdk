//! One command owner over the native selection actor; no receiver mutex/cache.
use crate::MarmotKitError;
use crate::conversions::*;
use std::sync::Arc;
#[derive(uniffi::Object)]
pub struct ChatSelection {
    pub(crate) inner: marmot_app::RuntimeChatListSelection,
}
impl ChatSelection {
    pub(crate) fn new(inner: marmot_app::RuntimeChatListSelection) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}
#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl ChatSelection {
    pub async fn status(&self) -> Result<ChatSelectionStatusFfi, MarmotKitError> {
        self.inner.status().await?.try_into()
    }
    pub async fn count(&self) -> Result<ChatSelectionSummaryFfi, MarmotKitError> {
        self.inner.count().await?.try_into()
    }
    pub async fn page(
        &self,
        revision: u64,
        offset: u64,
        limit: u32,
    ) -> Result<ChatSelectionPageFfi, MarmotKitError> {
        Ok(self
            .inner
            .page(revision, selection_offset(offset)?, limit as usize)
            .await?
            .into())
    }
    pub async fn folder_assignment_page(
        &self,
        revision: u64,
        context: ChatSelectionContextFfi,
        after: Option<String>,
        limit: u32,
    ) -> Result<ChatSelectionFolderPageFfi, MarmotKitError> {
        Ok(self
            .inner
            .folder_assignment_page(revision, context.into(), after, limit as usize)
            .await?
            .into())
    }
    pub async fn membership(
        &self,
        revision: u64,
        group_ids: Vec<String>,
    ) -> Result<Vec<bool>, MarmotKitError> {
        Ok(self.inner.membership(revision, group_ids).await?)
    }
    pub async fn exclude(
        &self,
        revision: u64,
        group_ids: Vec<String>,
    ) -> Result<ChatSelectionStatusFfi, MarmotKitError> {
        self.inner.exclude(revision, group_ids).await?.try_into()
    }
    /// Restores only explicitly unchecked original IDs before any operation starts.
    /// Fresh scope/presentation checks may return a new unresolved revision.
    /// Never reopen a full scope to implement a checkbox toggle.
    pub async fn reselect(
        &self,
        revision: u64,
        context: ChatSelectionContextFfi,
        group_ids: Vec<String>,
    ) -> Result<ChatSelectionStatusFfi, MarmotKitError> {
        self.inner
            .reselect(revision, context.into(), group_ids)
            .await?
            .try_into()
    }
    pub async fn presentation_page(
        &self,
        revision: u64,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<ChatSelectionOperandFfi>, MarmotKitError> {
        Ok(self
            .inner
            .presentation_page(revision, selection_offset(offset)?, limit as usize)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
    pub async fn submit_presentation(
        &self,
        revision: u64,
        host: ChatSelectionHostContextFfi,
        answers: Vec<ChatSelectionAnswerFfi>,
    ) -> Result<ChatSelectionStatusFfi, MarmotKitError> {
        self.inner
            .submit_presentation(
                revision,
                host.into(),
                answers.into_iter().map(Into::into).collect(),
            )
            .await?
            .try_into()
    }
    pub async fn resolve_presentation(
        &self,
        revision: u64,
    ) -> Result<ChatSelectionSummaryFfi, MarmotKitError> {
        self.inner.resolve_presentation(revision).await?.try_into()
    }
    pub async fn prepare_action_hints(
        &self,
        revision: u64,
        context: ChatSelectionContextFfi,
    ) -> Result<ChatSelectionStatusFfi, MarmotKitError> {
        self.inner
            .prepare_action_hints(revision, context.into())
            .await?
            .try_into()
    }
    pub async fn refresh_scope(
        &self,
        revision: u64,
        context: ChatSelectionContextFfi,
    ) -> Result<ChatSelectionStatusFfi, MarmotKitError> {
        self.inner
            .refresh_scope(revision, context.into())
            .await?
            .try_into()
    }
    /// Archive/local-delete primitive only. Group departure remains the existing
    /// guarded dialog/journal workflow, not a mapping to DeleteLocal.
    pub async fn apply(
        &self,
        operation_id: u64,
        attempt_id: u64,
        revision: u64,
        context: ChatSelectionContextFfi,
        mutation: ChatSelectionMutationFfi,
    ) -> Result<ChatSelectionMutationReportFfi, MarmotKitError> {
        self.inner
            .apply(
                operation_id,
                attempt_id,
                revision,
                context.into(),
                mutation.into(),
            )
            .await?
            .try_into()
    }
    pub async fn last_mutation(
        &self,
    ) -> Result<Option<ChatSelectionMutationReportFfi>, MarmotKitError> {
        self.inner
            .last_mutation()
            .await?
            .map(TryInto::try_into)
            .transpose()
    }
    pub async fn last_departure(
        &self,
    ) -> Result<Option<ChatSelectionDepartureReportFfi>, MarmotKitError> {
        Ok(self.inner.last_departure().await?.map(Into::into))
    }
    /// Retire this selection; generated host close() remains the object destructor.
    pub fn close_selection(&self) {
        self.inner.close();
    }
    pub fn cancel(&self) {
        self.inner.cancel();
    }
}
fn selection_offset(value: u64) -> Result<usize, MarmotKitError> {
    value
        .try_into()
        .map_err(|_| MarmotKitError::ChatSelectionInvalidSlots)
}
