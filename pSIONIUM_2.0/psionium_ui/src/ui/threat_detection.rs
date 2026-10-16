use warp::Filter;
use warp::http::StatusCode;

pub fn routes() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("threat_detection")
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "threats_detected": 5,
                "last_threat": "Ransomware, 3/20/25",
                "detection_rate": "99.5%"
            }))
        })
}