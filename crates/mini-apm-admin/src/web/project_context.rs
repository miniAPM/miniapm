use mini_apm::models::project::{self, Project};
use rama::http::StatusCode;
use rama::http::request::Parts;
use rama::http::service::web::extract::FromPartsStateRefPair;

use crate::AppState;
use crate::cookies::get_cookie_from_headers;

pub const PROJECT_COOKIE: &str = "miniapm_project";

/// Extracts current project context from cookie
#[derive(Clone, Debug)]
pub struct WebProjectContext {
    pub current_project: Option<Project>,
    pub projects: Vec<Project>,
    pub projects_enabled: bool,
    pub accounts_enabled: bool,
}

impl WebProjectContext {
    pub fn project_id(&self) -> Option<i64> {
        self.current_project.as_ref().map(|p| p.id)
    }

    /// Check if the given project ID is the current project (for template use)
    pub fn is_current_project(&self, id: &i64) -> bool {
        self.current_project.as_ref().map(|p| p.id) == Some(*id)
    }

    /// Returns true if project selector should be shown (more than 1 project)
    pub fn show_selector(&self) -> bool {
        self.projects.len() > 1
    }
}

/// The project picked with the project cookie, else the default project
impl FromPartsStateRefPair<AppState> for WebProjectContext {
    type Rejection = StatusCode;

    async fn from_parts_state_ref_pair(
        parts: &Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let projects = project::list_all(&state.pool).await.map_err(|e| {
            tracing::error!("Failed to load projects: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let wanted = get_cookie_from_headers(&parts.headers, PROJECT_COOKIE);
        let current_project = projects
            .iter()
            .find(|p| wanted.as_deref() == Some(p.slug.as_str()))
            .or_else(|| projects.iter().find(|p| p.slug == "default"))
            .or(projects.first())
            .cloned();

        Ok(Self {
            current_project,
            projects,
            projects_enabled: super::env_flag("ENABLE_PROJECTS"),
            accounts_enabled: super::env_flag("ENABLE_USER_ACCOUNTS"),
        })
    }
}
