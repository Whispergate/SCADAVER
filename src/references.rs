use std::sync::OnceLock;

use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct Reference {
    pub vendor: String,
    pub title: String,
    pub url: String,
    pub source: String,
}

static ALL: OnceLock<Vec<Reference>> = OnceLock::new();

pub fn all() -> &'static [Reference] {
    ALL.get_or_init(|| {
        serde_json::from_str(include_str!("data/references.json"))
            .expect("references.json malformed: re-run scripts/fetch_refs.py")
    })
}

pub fn for_vendor(slug: &str) -> Vec<&'static Reference> {
    all()
        .iter()
        .filter(|r| r.vendor == slug)
        .collect()
}

pub fn for_multi(vendors: &[String]) -> Vec<&'static Reference> {
    all()
        .iter()
        .filter(|r| vendors.iter().any(|v| r.vendor.as_str() == v.as_str()))
        .collect()
}
