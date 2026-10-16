use warp::Filter;
use warp::http::StatusCode;

pub fn routes() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("compliance")
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "compliance_status": "Green",
                "last_audit": "3/18/25",
                "log_size": "5 MB"
            }))
        })
}