// DELIBERATELY VULNERABLE: for lab/education only
use actix_cors::Cors;
use actix_web::{cookie::Cookie, get, http, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use md5::{Digest, Md5};
use rand::Rng;
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::fs;
use std::process::Command;

// Hard-coded credentials and security constants (vulnerability).
const ADMIN_USER: &str = "admin";
const ADMIN_PASS: &str = "P@ssw0rd123"; // Hard-coded credential (vulnerable)
const STATIC_KEY: &str = "DEADBEEF_DEMO_KEY"; // Hard-coded security constant

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct EchoQuery {
    msg: String,
}

#[derive(Deserialize)]
struct FileQuery {
    path: String,
}

#[derive(Deserialize)]
struct SqlQuery {
    username: String,
}

#[derive(Deserialize)]
struct LdapQuery {
    uid: String,
}

#[derive(Deserialize)]
struct RedirectQuery {
    url: String,
}

#[derive(Deserialize)]
struct FetchQuery {
    url: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize a very simple SQLite DB (vulnerable to SQL injection below).
    let conn = Connection::open_in_memory().expect("open DB");
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?1, ?2)",
        params!["alice", "alicepw"],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?1, ?2)",
        params!["bob", "bobpw"],
    )
    .unwrap();

    // Move connection into app data
    let conn_data = web::Data::new(conn);

    println!("Vulnerable server running at http://127.0.0.1:8080");
    HttpServer::new(move || {
        // Permissive CORS policy (vulnerable). Allows any origin and credentials.
        let cors = Cors::default()
            .allow_any_origin() // Permissive cross-domain security policy
            .allow_any_method()
            .allow_any_header()
            .supports_credentials();

        App::new()
            .wrap(cors)
            .app_data(conn_data.clone())
            .service(index)
            .service(login)
            .service(echo)
            .service(read_file)
            .service(sql_lookup)
            .service(ldap_lookup)
            .service(exec_cmd)
            .service(md5_hash) // shows weak hash / broken algorithm
            .service(open_redirect)
            .service(fetch_url) // SSRF
            .route("/set_cookie", web::get().to(set_insecure_cookie))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[get("/")]
async fn index() -> impl Responder {
    // Reflects unsanitized content -> XSS risk when rendered in HTML
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(r#"<h1>Vulnerable Rust App (lab)</h1>
<p>Try endpoints like: /echo?msg=... /read_file?path=... /exec_cmd?cmd=... /sql_lookup?username=...</p>"#)
}

/// LOGIN endpoint using hard-coded credentials (vulnerable)
#[post("/login")]
async fn login(form: web::Json<LoginForm>) -> impl Responder {
    // Use of hard-coded credentials (in constants above)
    if form.username == ADMIN_USER && form.password == ADMIN_PASS {
        // Use of insufficient randomness for session token (vulnerable)
        let token: u32 = rand::thread_rng().gen(); // insufficiently random for auth tokens
        let resp_body = format!("Welcome {}, token: {}", form.username, token);
        HttpResponse::Ok().body(resp_body)
    } else {
        HttpResponse::Unauthorized().body("Invalid")
    }
}

/// Reflected XSS example (no escaping)
#[get("/echo")]
async fn echo(q: web::Query<EchoQuery>) -> impl Responder {
    // Improper neutralization of special elements -> XSS when displayed in HTML
    let html = format!("<html><body><h2>Echo</h2><div>{}</div></body></html>", q.msg);
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

/// Path traversal demo (reads arbitrary file path supplied by user)
#[get("/read_file")]
async fn read_file(q: web::Query<FileQuery>) -> impl Responder {
    // Vulnerable to path traversal: no normalization or jail
    // e.g. /read_file?path=../../etc/passwd
    match fs::read_to_string(&q.path) {
        Ok(contents) => HttpResponse::Ok().body(contents),
        Err(e) => HttpResponse::BadRequest().body(format!("Error: {}", e)),
    }
}

/// SQL Injection demo (string concatenation)
#[get("/sql_lookup")]
async fn sql_lookup(q: web::Query<SqlQuery>, conn: web::Data<Connection>) -> impl Responder {
    // Vulnerable: concatenating user input into SQL
    let query = format!("SELECT id, username FROM users WHERE username = '{}';", q.username);
    // This is intentionally insecure; no prepared statements or parameterization
    let mut stmt = match conn.prepare(&query) {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().body(format!("DB prepare error: {}", e)),
    };

    let mut rows = match stmt.query([]) {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().body(format!("DB query error: {}", e)),
    };
    if let Some(row) = rows.next().unwrap_or(None) {
        let id: i64 = row.get(0).unwrap_or(-1);
        let username: String = row.get(1).unwrap_or_default();
        HttpResponse::Ok().body(format!("Found user: {} (id {})", username, id))
    } else {
        HttpResponse::Ok().body("No user")
    }
}

/// LDAP injection demo (simulated - constructs LDAP filter from user input unsafely)
#[get("/ldap_lookup")]
async fn ldap_lookup(q: web::Query<LdapQuery>) -> impl Responder {
    // Constructing LDAP filter by concatenation -> LDAP Injection
    let ldap_filter = format!("(uid={})", q.uid);
    // For demo we just return the filter string (would be sent to LDAP server in real app)
    HttpResponse::Ok().body(format!("Constructed LDAP filter: {}", ldap_filter))
}

/// OS Command Injection demo (executes user-supplied command string)
#[get("/exec_cmd")]
async fn exec_cmd(req: HttpRequest) -> impl Responder {
    // Get raw query param "cmd" (vulnerable)
    if let Some(qs) = req.uri().query() {
        // naive parse for cmd=...
        for pair in qs.split('&') {
            if let Some(rest) = pair.strip_prefix("cmd=") {
                // Directly feed to shell -> command injection
                #[cfg(target_family = "unix")]
                {
                    let output = Command::new("sh")
                        .arg("-c")
                        .arg(rest)
                        .output()
                        .unwrap_or_else(|e| panic!("failed to execute: {}", e));
                    let out = String::from_utf8_lossy(&output.stdout);
                    return HttpResponse::Ok().body(format!("Output:\n{}", out));
                }
                #[cfg(target_family = "windows")]
                {
                    let output = Command::new("cmd")
                        .arg("/C")
                        .arg(rest)
                        .output()
                        .unwrap_or_else(|e| panic!("failed to execute: {}", e));
                    let out = String::from_utf8_lossy(&output.stdout);
                    return HttpResponse::Ok().body(format!("Output:\n{}", out));
                }
            }
        }
    }
    HttpResponse::BadRequest().body("Missing cmd param")
}

/// MD5 hashing endpoint — demonstrates weak hash / broken algorithm & use of a static key
#[post("/md5")]
async fn md5_hash(body: web::Bytes) -> impl Responder {
    // Weak hash (MD5) and use of static key (STATIC_KEY) for "integrity"
    let mut hasher = Md5::new();
    hasher.update(&body);
    hasher.update(STATIC_KEY.as_bytes()); // hard-coded key usage
    let result = hasher.finalize();
    HttpResponse::Ok().body(format!("{:x}", result))
}

/// Open redirect (no validation)
#[get("/redirect")]
async fn open_redirect(q: web::Query<RedirectQuery>) -> impl Responder {
    // Unsafe redirect to user-controlled URL -> open redirect
    HttpResponse::Found()
        .insert_header((http::header::LOCATION, q.url.clone()))
        .finish()
}

/// SSRF demo: server fetches arbitrary URL supplied by user
#[get("/fetch")]
async fn fetch_url(q: web::Query<FetchQuery>) -> impl Responder {
    // No validation of URL -> SSRF
    // Blocking reqwest for simplicity
    match reqwest::blocking::get(&q.url) {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().unwrap_or_else(|_| "<failed to read>".to_string());
            HttpResponse::Ok().body(format!("Status: {}\nBody:\n{}", status, text))
        }
        Err(e) => HttpResponse::BadRequest().body(format!("Request error: {}", e)),
    }
}

/// Endpoint that sets a cookie without HttpOnly flag (sensitive cookie leaking to JS)
async fn set_insecure_cookie() -> impl Responder {
    let mut response = HttpResponse::Ok();
    // Sensitive cookie but not marked HttpOnly -> accessible via JS (vulnerable)
    let cookie = Cookie::build("session_id", "insecure-session-token-123")
        .path("/")
        // do not set http_only
        .finish();
    response.add_cookie(&cookie).ok();
    response.body("Cookie set (not HttpOnly)")
}
