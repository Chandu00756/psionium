use warp::Filter;
use warp::http::StatusCode;

pub fn routes() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("update_manager")
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "last_update": "3/1/25",
                "threat_db": "15K Entries",
                "patch_status": "Up-to-date"
            }))
        })
}