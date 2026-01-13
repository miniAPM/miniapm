use mini_apm::models::project::Project;

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
