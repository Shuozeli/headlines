//! Static plan data: account display names, follow edges, scopes.

/// Per-account display config the seed uses for `CreateAccount`.
pub struct AccountSpec {
    pub short_name: &'static str,
    pub author_name: &'static str,
    pub author_url: &'static str,
}

pub const ACCOUNTS: &[(&str, AccountSpec)] = &[
    (
        "techblog",
        AccountSpec {
            short_name: "techblog",
            author_name: "TechBlog Editorial",
            author_url: "https://example.com/techblog",
        },
    ),
    (
        "worldnews",
        AccountSpec {
            short_name: "worldnews",
            author_name: "World News Desk",
            author_url: "https://example.com/worldnews",
        },
    ),
    (
        "tutorials",
        AccountSpec {
            short_name: "tutorials",
            author_name: "Tutorials Team",
            author_url: "https://example.com/tutorials",
        },
    ),
    (
        "opinion",
        AccountSpec {
            short_name: "opinion",
            author_name: "Opinion Page",
            author_url: "https://example.com/opinion",
        },
    ),
    (
        "videos",
        AccountSpec {
            short_name: "videos",
            author_name: "Videos Studio",
            author_url: "https://example.com/videos",
        },
    ),
];

/// User display config.
pub const USERS: &[(&str, &str)] = &[
    ("alice", "Alice Reader"),
    ("bob", "Bob Reader"),
    ("carol", "Carol Reader"),
    ("dave", "Dave Reader"),
    ("eve", "Eve Reader"),
    ("frank", "Frank Reader"),
    ("grace", "Grace Reader"),
];

/// System scope plan.
pub const SYSTEMS: &[(&str, &[&str])] = &[
    (
        "demo-ranker",
        &[
            "feeds.recommendation.write",
            "feeds.recommendation.read",
            "events.read",
            "articles.stream",
        ],
    ),
    (
        "demo-admin",
        &[
            "accounts.write",
            "accounts.admin",
            "accounts.delete",
            "articles.write",
            "articles.tombstone",
            "articles.redact",
            "articles.stream",
            "events.read",
            "events.write",
            "users.admin",
            "feeds.recommendation.write",
            "feeds.recommendation.read",
            "admin.*",
        ],
    ),
];

/// Hardcoded follow edges: (user, account) pairs. Mix of users following
/// some/all/none of the publishers so the demo feeds aren't identical.
pub const FOLLOWS: &[(&str, &[&str])] = &[
    ("alice", &["techblog", "tutorials"]),
    ("bob", &["worldnews"]),
    (
        "carol",
        &["techblog", "worldnews", "tutorials", "opinion", "videos"],
    ),
    ("dave", &["opinion", "videos"]),
    ("eve", &["techblog", "videos"]),
    ("frank", &["worldnews", "opinion"]),
    ("grace", &["tutorials"]),
];
