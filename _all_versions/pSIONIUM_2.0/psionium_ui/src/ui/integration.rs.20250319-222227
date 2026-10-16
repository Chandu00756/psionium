use warp::Filter;
use warp::http::StatusCode;

pub fn routes() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("integration")
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "os": "Windows 10",
                "integration": "Kernel Module Active",
                "footprint": "45 MB RAM"
            }))
        })
}