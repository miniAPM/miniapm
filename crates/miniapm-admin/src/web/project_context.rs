use tower_cookies::Cookies;

use miniapm::{DbPool, models::project::Project};

pub const PROJECT_COOKIE: &str = "miniapm_project";

/// Extracts current project context from cookie
#[derive(Clone, Debug)]
pub struct WebProjectContext {
    pub current_project: Option<Project>,
    pub projects: Vec<Project>,
    pub projects_enabled: bool,
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
        self.projects_enabled && self.projects.len() > 1
    }
}

pub fn get_project_context(pool: &DbPool, cookies: &Cookies) -> WebProjectContext {
    let projects_enabled = std::env::var("ENABLE_PROJECTS")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);

    if !projects_enabled {
        return WebProjectContext {
            current_project: None,
            projects: vec![],
            projects_enabled: false,
        };
    }

    let projects = miniapm::models::project::list_all(pool).unwrap_or_default();

    // Get project slug from cookie
    let project_slug = cookies.get(PROJECT_COOKIE).map(|c| c.value().to_string());

    let current_project = match project_slug {
        Some(slug) => projects.iter().find(|p| p.slug == slug).cloned(),
        None => projects.first().cloned(),
    };

    WebProjectContext {
        current_project,
        projects,
        projects_enabled,
    }
}
