def get_allowed_origins() -> list[str]:
    default_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://mango-pebble-099d8de00.7.azurestaticapps.net",
    ]

    configured_origins = os.getenv(
        "CORS_ORIGINS",
        "",
    ).strip()

    if not configured_origins:
        return default_origins

    origins = [
        origin.strip().rstrip("/")
        for origin in configured_origins.split(",")
        if origin.strip()
    ]

    return list(
        dict.fromkeys(
            [
                *default_origins,
                *origins,
            ]
        )
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_origin_regex=(
        r"https://.*\.azurestaticapps\.net"
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=86400,
)