// web_integration.rs — HTTP layer tests for the scadaver web API.
//
// Tests the axum router directly via tower::ServiceExt, no TCP server needed.
// Protocol logic is covered by ops_integration.rs; these tests cover:
//   - Route existence and HTTP status codes
//   - JSON response shapes for cached device data
//   - Auth rejection on missing/wrong token
//   - 404 on unknown routes
//
// Run: cargo test --test web_integration

// NOTE: these tests require `build_router` and `Database` to be exposed from the library.
// Current status: routes.rs is not yet part of the lib target (it's cli-feature-gated
// behind the binary). To enable, add `pub mod web;` to lib.rs with cfg(feature = "cli")
// and ensure build_router is pub.
//
// This file is a placeholder until that wiring is done.

// Uncomment when web module is exported from lib:
//
// use axum::body::Body;
// use axum::http::{Request, StatusCode};
// use tower::ServiceExt;
//
// fn open_temp_db() -> scadaver::db::Database {
//     let tmp = tempfile::NamedTempFile::new().unwrap();
//     scadaver::db::Database::open(tmp.path()).unwrap()
// }
//
// #[tokio::test]
// async fn web_health_returns_200() {
//     let db = open_temp_db();
//     let app = scadaver::web::routes::build_router(db);
//     let response = app
//         .oneshot(Request::builder().uri("/api/devices").body(Body::empty()).unwrap())
//         .await
//         .unwrap();
//     assert_eq!(response.status(), StatusCode::OK);
// }
//
// #[tokio::test]
// async fn web_unknown_route_returns_404() {
//     let db = open_temp_db();
//     let app = scadaver::web::routes::build_router(db);
//     let response = app
//         .oneshot(Request::builder().uri("/does-not-exist").body(Body::empty()).unwrap())
//         .await
//         .unwrap();
//     assert_eq!(response.status(), StatusCode::NOT_FOUND);
// }

// Placeholder so the file compiles during the transition period.
#[test]
fn web_placeholder_always_passes() {
    // Remove once the real web tests above are uncommented.
}
