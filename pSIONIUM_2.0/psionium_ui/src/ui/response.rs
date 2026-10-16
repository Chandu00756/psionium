use warp::Filter;
use warp::http::StatusCode;

pub fn routes() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("response")
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "actions_taken": 3,
                "last_action": "Terminated Process 1234",
                "recovery_status": "100%"
            }))
        })
}