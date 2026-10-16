use warp::Filter;
use warp::filters::path::FullPath;
use warp::http::StatusCode;
use std::collections::HashMap;

pub fn routes() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path::end()
        .and(warp::get())
        .map(|| {
            let mut data = HashMap::new();
            data.insert("status", "Protected");
            data.insert("threats_blocked", "5");
            data.insert("last_update", "3/20/25");
            warp::reply::html(include_str!("../assets/templates/index.html"))
        })
}