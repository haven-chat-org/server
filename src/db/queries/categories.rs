use uuid::Uuid;

use crate::db::Pool;
use crate::errors::AppResult;
use crate::models::*;

// ─── Channel Categories ─────────────────────────────────

pub async fn create_category(
    pool: &Pool,
    server_id: Uuid,
    name: &str,
    position: i32,
) -> AppResult<ChannelCategory> {
    let cat = sqlx::query_as::<_, ChannelCategory>(
        r#"
        INSERT INTO channel_categories (server_id, name, position)
        VALUES ($1, $2, $3)
        RETURNING *
        "#,
    )
    .bind(server_id)
    .bind(name)
    .bind(position)
    .fetch_one(pool)
    .await?;
    Ok(cat)
}

pub async fn get_server_categories(pool: &Pool, server_id: Uuid) -> AppResult<Vec<ChannelCategory>> {
    let cats = sqlx::query_as::<_, ChannelCategory>(
        "SELECT * FROM channel_categories WHERE server_id = $1 ORDER BY position ASC",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;
    Ok(cats)
}

pub async fn find_category_by_id(pool: &Pool, category_id: Uuid) -> AppResult<Option<ChannelCategory>> {
    let cat = sqlx::query_as::<_, ChannelCategory>(
        "SELECT * FROM channel_categories WHERE id = $1",
    )
    .bind(category_id)
    .fetch_optional(pool)
    .await?;
    Ok(cat)
}

pub async fn update_category(
    pool: &Pool,
    category_id: Uuid,
    name: Option<&str>,
    position: Option<i32>,
) -> AppResult<ChannelCategory> {
    let cat = sqlx::query_as::<_, ChannelCategory>(
        r#"
        UPDATE channel_categories
        SET name = COALESCE($2, name),
            position = COALESCE($3, position)
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(category_id)
    .bind(name)
    .bind(position)
    .fetch_one(pool)
    .await?;
    Ok(cat)
}

pub async fn delete_category(pool: &Pool, category_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM channel_categories WHERE id = $1")
        .bind(category_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn reorder_categories(
    pool: &Pool,
    server_id: Uuid,
    order: &[(Uuid, i32)],
) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    for (cat_id, pos) in order {
        sqlx::query(
            "UPDATE channel_categories SET position = $1 WHERE id = $2 AND server_id = $3",
        )
        .bind(pos)
        .bind(cat_id)
        .bind(server_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn reorder_channels(
    pool: &Pool,
    server_id: Uuid,
    order: &[(Uuid, i32, Option<Uuid>)],
) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    for (channel_id, pos, category_id) in order {
        sqlx::query(
            "UPDATE channels SET position = $1, category_id = $2 WHERE id = $3 AND server_id = $4",
        )
        .bind(pos)
        .bind(category_id)
        .bind(channel_id)
        .bind(server_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn set_channel_category(
    pool: &Pool,
    channel_id: Uuid,
    category_id: Option<Uuid>,
) -> AppResult<Channel> {
    let channel = sqlx::query_as::<_, Channel>(
        r#"
        UPDATE channels SET category_id = $2 WHERE id = $1 RETURNING *
        "#,
    )
    .bind(channel_id)
    .bind(category_id)
    .fetch_one(pool)
    .await?;
    Ok(channel)
}
