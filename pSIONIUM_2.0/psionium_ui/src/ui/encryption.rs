use warp::Filter;
use warp::http::StatusCode;

pub fn routes() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("encryption")
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "active": true,
                "key_strength": "4096-bit Kyber",
                "files_encrypted": 1234
            }))
        })
}