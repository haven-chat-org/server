pub mod queries;

use crate::config::AppConfig;

// ─── Database-Agnostic Pool Types ─────────────────────
//
// Exactly one of `postgres` or `sqlite` feature must be enabled.
// The Pool type alias makes the rest of the codebase database-agnostic.

#[cfg(all(feature = "postgres", feature = "sqlite"))]
compile_error!("Features `postgres` and `sqlite` are mutually exclusive. Enable only one.");

#[cfg(not(any(feature = "postgres", feature = "sqlite")))]
compile_error!("Either `postgres` or `sqlite` feature must be enabled.");

#[cfg(feature = "postgres")]
pub type Pool = sqlx::PgPool;

#[cfg(feature = "sqlite")]
pub type Pool = sqlx::SqlitePool;

/// Wraps primary and optional replica database pools.
/// Read queries go to the replica (if available), writes always go to primary.
#[derive(Clone)]
pub struct DbPools {
    primary: Pool,
    replica: Option<Pool>,
}

impl DbPools {
    /// Initialize pools from config. Runs migrations on the primary.
    pub async fn init(config: &AppConfig) -> Self {
        #[cfg(feature = "postgres")]
        let primary = {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(config.db_max_connections)
                .connect(&config.database_url)
                .await
                .expect("Failed to connect to PostgreSQL (primary)");

            sqlx::migrate!("./migrations")
                .run(&pool)
                .await
                .expect("Failed to run database migrations");

            tracing::info!("PostgreSQL connected and migrations applied");
            pool
        };

        #[cfg(feature = "sqlite")]
        let primary = {
            // Ensure parent directory exists for SQLite file
            if let Some(path) = config.database_url.strip_prefix("sqlite:") {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    std::fs::create_dir_all(parent).ok();
                }
            }

            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(config.db_max_connections)
                .connect(&config.database_url)
                .await
                .expect("Failed to connect to SQLite");

            // Enable WAL mode for better concurrent read/write performance
            sqlx::query("PRAGMA journal_mode=WAL")
                .execute(&pool)
                .await
                .ok();
            sqlx::query("PRAGMA foreign_keys=ON")
                .execute(&pool)
                .await
                .ok();

            sqlx::migrate!("./migrations_sqlite")
                .run(&pool)
                .await
                .expect("Failed to run database migrations");

            tracing::info!("SQLite connected and migrations applied");
            pool
        };

        // Replica support (PostgreSQL only)
        #[cfg(feature = "postgres")]
        let replica = if config.database_replica_url.is_empty() {
            None
        } else {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(config.db_max_connections)
                .connect(&config.database_replica_url)
                .await
                .expect("Failed to connect to PostgreSQL (replica)");
            tracing::info!("Read replica connected");
            Some(pool)
        };

        #[cfg(feature = "sqlite")]
        let replica: Option<Pool> = None; // SQLite doesn't support replicas

        Self { primary, replica }
    }

    /// Read queries — returns replica if available, else primary.
    pub fn read(&self) -> &Pool {
        self.replica.as_ref().unwrap_or(&self.primary)
    }

    /// Write queries — always primary.
    pub fn write(&self) -> &Pool {
        &self.primary
    }

    /// Direct access to primary (for migrations, background workers, etc).
    pub fn primary(&self) -> &Pool {
        &self.primary
    }

    /// Single-pool constructor for tests (no replica).
    #[cfg(feature = "postgres")]
    pub fn from_single(pool: Pool) -> Self {
        Self {
            primary: pool,
            replica: None,
        }
    }

    /// Single-pool constructor for tests (no replica).
    #[cfg(feature = "sqlite")]
    pub fn from_single(pool: Pool) -> Self {
        Self {
            primary: pool,
            replica: None,
        }
    }
}

/// Initialize a single database connection pool and run migrations.
/// Kept for backward compatibility; prefer `DbPools::init` for production.
#[cfg(feature = "postgres")]
pub async fn init_pool(config: &AppConfig) -> Pool {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run database migrations");

    tracing::info!("Database connected and migrations applied");
    pool
}
