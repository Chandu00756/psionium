mod ui;

use warp::Filter;
use log::info;
use env_logger;
use tokio;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    info!("Starting Psionium UI server");

    let routes = ui::dashboard::routes()
        .or(ui::encryption::routes())
        .or(ui::threat_detection::routes())
        .or(ui::response::routes())
        .or(ui::compliance::routes())
        .or(ui::integration::routes())
        .or(ui::update_manager::routes());

    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
    Ok(())
}