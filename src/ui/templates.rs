use askama::Template;

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub domains: Vec<DomainSummary>,
}

pub struct DomainSummary {
    pub id: String,
    pub domain: String,
    pub verified: bool,
    pub link_count: u64,
}

#[derive(Template)]
#[template(path = "domain_detail.html")]
pub struct DomainDetailTemplate {
    pub domain: DomainInfo,
}

pub struct DomainInfo {
    pub id: String,
    pub domain: String,
    pub verified: bool,
    pub challenge_type: String,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "token_management.html")]
pub struct TokenManagementTemplate {
    pub domain_id: String,
    pub domain_name: String,
    pub tokens: Vec<TokenSummary>,
}

pub struct TokenSummary {
    pub name: String,
    pub allowed_rels: String,
    pub resource_pattern: String,
    pub created_at: String,
    pub revoked: bool,
}

#[derive(Template)]
#[template(path = "link_browser.html")]
pub struct LinkBrowserTemplate {
    pub domain_id: String,
    pub domain_name: String,
    pub links: Vec<LinkSummary>,
}

pub struct LinkSummary {
    pub resource_uri: String,
    pub rel: String,
    pub href: String,
    pub link_type: String,
    pub expires_at: String,
}
