#![feature(proc_macro_hygiene, decl_macro)]
use bstr::ByteSlice;
use log::error;
use rocket::{
    fairing::AdHoc,
    http::Method,
    request::{FromRequest, Outcome, Request},
    State,
};
use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::PathBuf;

#[macro_use]
extern crate rocket;

#[derive(Debug, Serialize, Deserialize)]
pub struct SorterError {
    kind: ErrorKind,
    code: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ErrorKind {
    IoError,
    SourceNotFound(String),
    DestinationNotFound(String),
    DestinationExists(String),
    MoveFailed,
    CommandFailed,
    InternalError,
    UnknownUser,
    SourceDoesNotExists(String),
}
impl ErrorKind {
    fn code(&self) -> u64 {
        match self {
            Self::IoError => 0,
            Self::SourceNotFound(_) => 1,
            Self::DestinationNotFound(_) => 2,
            Self::MoveFailed => 3,
            Self::CommandFailed => 4,
            Self::InternalError => 5,
            Self::UnknownUser => 6,
            Self::DestinationExists(_) => 7,
            Self::SourceDoesNotExists(_) => 8,
        }
    }
}
impl From<ErrorKind> for SorterError {
    fn from(kind: ErrorKind) -> Self {
        SorterError {
            code: kind.code(),
            kind,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
enum Status {
    Error,
    Success,
}
#[derive(Serialize, Deserialize, Debug)]
struct Response<T, E> {
    status: Status,
    error: Option<E>,
    response: Option<T>,
}

type JsonResult<T> = Json<Response<T, SorterError>>;

impl<T, E> From<Result<T, E>> for Response<T, E> {
    fn from(result: Result<T, E>) -> Self {
        match result {
            Ok(ok) => Response {
                status: Status::Success,
                error: None,
                response: Some(ok),
            },
            Err(e) => Response {
                status: Status::Error,
                error: Some(e),
                response: None,
            },
        }
    }
}

fn resp<T>(response: T) -> JsonResult<T> {
    Json(Response::from(Ok(response)))
}
fn err<T>(error: ErrorKind) -> JsonResult<T> {
    Json(Response::from(Err(SorterError::from(error))))
}

#[derive(Debug)]
enum AuthError {
    GuardFetch,
    InvalidAuthorization,
    TokenExpired,
}
#[derive(Debug)]
struct User {
    name: String,
}

impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = AuthError;
    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        let secret = request
            .guard::<State<Secret>>()
            .map_failure(|(s, _)| (s, AuthError::GuardFetch))?;

        let auth = match request.headers().get_one("Authorization") {
            Some(a) => a,
            None => {
                return rocket::Outcome::Failure((
                    rocket::http::Status::BadRequest,
                    AuthError::InvalidAuthorization,
                ))
            }
        };
        if !auth.starts_with("Bearer") {
            error!("Authorization does not start with Bearer");
            return rocket::Outcome::Failure((
                rocket::http::Status::BadRequest,
                AuthError::InvalidAuthorization,
            ));
        }
        let auth = auth.trim_start_matches("Bearer").trim_start();
        let decoded = match jsonwebtoken::decode::<Claims>(
            auth,
            &secret.jwt_key,
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
        ) {
            Err(e) => {
                error!("Could not decode JWT: {:?}", e);
                return rocket::Outcome::Failure((
                    rocket::http::Status::BadRequest,
                    AuthError::InvalidAuthorization,
                ));
            }
            Ok(d) => d,
        };
        if decoded.claims.iat + chrono::Duration::seconds(decoded.claims.exp as i64)
            < chrono::Utc::now()
        {
            return rocket::Outcome::Failure((
                rocket::http::Status::Unauthorized,
                AuthError::TokenExpired,
            ));
        }
        Outcome::Success(User {
            name: decoded.claims.sub,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Login {
    password: String,
    username: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct LoginResult {
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: chrono::DateTime<chrono::Utc>,
}

#[post("/login", data = "<login>")]
fn login(
    login: Json<Login>,
    secret: State<Secret>,
    users: State<Users>,
) -> JsonResult<LoginResult> {
    let login = login.into_inner();
    if let None | Some(false) = users
        .users
        .get(&login.username)
        .map(|details| details.password == login.password)
    {
        return err(ErrorKind::UnknownUser);
    };

    let claims = Claims {
        sub: login.username,
        exp: secret.exp,
        iat: chrono::Utc::now(),
    };
    let token =
        match jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &secret.jwt_key) {
            Ok(t) => t,
            Err(e) => {
                log::error!("Error encoding token: {:?}", e);
                return err(ErrorKind::InternalError);
            }
        };
    resp(LoginResult { token })
}

#[derive(Serialize, Deserialize, Debug)]
struct File {
    source: String,
    name: PathBuf,
}
#[derive(Serialize, Deserialize, Debug)]
struct Files {
    files: HashMap<String, Vec<PathBuf>>,
}

fn list_files_source(name: &str, source: &Source) -> Result<Vec<PathBuf>, ErrorKind> {
    let mut files = Vec::new();
    match std::fs::read_dir(&source.path) {
        Err(e) => {
            error!("Error reading source {}: {:?}", name, e);
            Err(ErrorKind::IoError)?;
        }
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Err(e) => {
                        error!("Error reading source {}: {:?}", name, e);
                        Err(ErrorKind::IoError)?;
                    }
                    Ok(entry) => {
                        files.push(entry.path().strip_prefix(&source.path).unwrap().to_owned())
                    }
                }
            }
        }
    }

    Ok(files)
}

#[get("/files")]
fn list_files(user: User, sources: State<Sources>, users: State<Users>) -> JsonResult<Files> {
    let details = users.users.get(&user.name).unwrap();
    let mut files = HashMap::new();
    for (name, source) in &sources.sources {
        if details.sources.contains(name) {
            let mut files_for_source = match list_files_source(&name, source) {
                Ok(f) => f,
                Err(e) => return err(e),
            };
            files
                .entry(name.into())
                .or_insert_with(Vec::new)
                .append(&mut files_for_source);
        }
    }
    resp(Files { files })
}
#[get("/files/<source>")]
fn list_files_in_source(
    source: String,
    sources: State<Sources>,
    users: State<Users>,
    user: User,
) -> JsonResult<Files> {
    if !users
        .users
        .get(&user.name)
        .unwrap()
        .sources
        .contains(&source)
    {
        return err(ErrorKind::SourceNotFound(source));
    }
    match sources.sources.get(&source) {
        None => err(ErrorKind::SourceNotFound(source)),
        Some(s) => match list_files_source(&source, s) {
            Err(e) => err(e),
            Ok(files) => {
                let mut map = HashMap::new();
                map.insert(source, files);
                resp(Files { files: map })
            }
        },
    }
}

#[get("/sources")]
fn list_sources(users: State<Users>, user: User) -> JsonResult<Vec<String>> {
    resp(
        users
            .users
            .get(&user.name)
            .unwrap()
            .sources
            .iter()
            .cloned()
            .collect(),
    )
}

#[get("/destinations")]
fn list_destinations(_user: User, destinations: State<Destinations>) -> JsonResult<Vec<String>> {
    resp(destinations.destinations.keys().cloned().collect())
}

#[put("/files/<source>/<file>/<destination>")]
fn move_file(
    source: String,
    file: String,
    destination: String,
    sources: State<Sources>,
    destinations: State<Destinations>,
    user: User,
    users: State<Users>,
) -> JsonResult<()> {
    if !users
        .users
        .get(&user.name)
        .unwrap()
        .sources
        .contains(&source)
    {
        return err(ErrorKind::SourceNotFound(source));
    }

    let source_name = source;
    let source = match sources.sources.get(&source_name) {
        Some(s) => s,
        None => return err(ErrorKind::SourceNotFound(source_name)),
    };
    let mut source_file = source.path.clone();
    source_file.push(&file);
    if !source_file.exists() {
        return err(ErrorKind::SourceDoesNotExists(file));
    }

    let destination_name = destination;
    let destination = match destinations.destinations.get(&destination_name) {
        Some(d) => d,
        None => return err(ErrorKind::DestinationNotFound(destination_name)),
    };
    let mut destination_file = destination.path.clone();
    destination_file.push(&file);
    if destination_file.exists() {
        return err(ErrorKind::DestinationExists(file));
    }
    if let Err(e) = std::fs::rename(source_file, &destination_file) {
        error!("Could not move file to {:?}: {:?}", destination_file, e);
        return err(ErrorKind::MoveFailed);
    }
    if let Some(actions) = &destination.actions {
        for action_name in actions {
            let action = destinations
                .actions
                .get(action_name)
                .expect("action not present");
            let mut command = action.command.clone();
            if let Some(infos) = &action.infos {
                for info in infos {
                    match info {
                        Info::Name => command = command.replace("!name", &file),
                        Info::Path => {
                            command = command.replace("!path", destination_file.to_str().unwrap())
                        }
                    }
                }
            }
            if let Some(params) = &destination.params {
                for (param, value) in params {
                    if let Some(command_params) = &action.params {
                        if command_params.contains(param) {
                            command = command.replace(&format!("#{}", param), value);
                        }
                    }
                }
            }
            let mut command = command.split_whitespace();
            let base = command.next().unwrap();
            let args = command;
            let mut command = std::process::Command::new(base);
            command.args(args);
            let output = match command.output() {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("Can't run action {}: {:?}", base, e);
                    return err(ErrorKind::CommandFailed);
                }
            };
            if !output.stderr.is_empty() {
                log::warn!("Action {} failed: {}", action_name, output.stderr.as_bstr());
            }
            if !output.stdout.is_empty() {
                println!("Action {}: {}", action_name, output.stdout.as_bstr());
            }
        }
    }
    resp(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Destination {
    path: PathBuf,
    actions: Option<Vec<String>>,
    params: Option<HashMap<String, String>>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Source {
    path: PathBuf,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Action {
    command: String,
    params: Option<Vec<String>>,
    infos: Option<Vec<Info>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Info {
    #[serde(rename = "name")]
    Name,
    #[serde(rename = "path")]
    Path,
}

#[derive(Debug, Serialize, Deserialize)]
struct Destinations {
    destinations: HashMap<String, Destination>,
    actions: HashMap<String, Action>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Sources {
    sources: HashMap<String, Source>,
}
#[derive(Debug, Serialize, Deserialize)]
struct UserDetails {
    password: String,
    sources: HashSet<String>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Users {
    users: HashMap<String, UserDetails>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Secret {
    jwt_key: Vec<u8>,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    destinations: HashMap<String, Destination>,
    sources: HashMap<String, Source>,
    actions: HashMap<String, Action>,
    users: HashMap<String, UserDetails>,
    secret: String,
    expiry: usize,
}

fn validate_destinations(
    destinations: &HashMap<String, Destination>,
    actions: &HashMap<String, Action>,
) -> Result<(), ()> {
    for (name, action) in actions {
        if action.command.is_empty() {
            error!("Action {}: needs a non empty command", name);
            Err(())?
        }
    }
    for (name, destination) in destinations {
        let dest_actions = match &destination.actions {
            Some(a) => a,
            None => continue,
        };
        for action_name in dest_actions {
            match actions.get(action_name) {
                Some(action) => {
                    if let Some(params) = &action.params {
                        for param in params {
                            match &destination.params {
                                None => {
                                    error!("Destination {}: a param was expected, but none were provided", name);
                                    Err(())?;
                                }
                                Some(dest_param) => {
                                    if !dest_param.contains_key(param) {
                                        error!("Destination {}: param {} was expected but not provided (because of action {})",name, param, action_name);
                                        Err(())?
                                    }
                                }
                            }
                        }
                    }
                }
                None => {
                    error!("Action {} is unknown in destination {}", action_name, name);
                    Err(())?
                }
            }
        }
    }
    Ok(())
}

fn parse_config(path: impl AsRef<std::path::Path>) -> Result<Config, ()> {
    let mut config = std::fs::File::open(path).map_err(|e| {
        error!("Error opening config: {:?}", e);
    })?;
    let mut config_content = Vec::new();
    config.read_to_end(&mut config_content).map_err(|e| {
        error!("Error reading config: {:?}", e);
    })?;
    toml::from_slice(&config_content).map_err(|e| {
        error!("Error parsing config: {:?}", e);
    })
}

fn main() -> anyhow::Result<()> {
    let allowed_origins = rocket_cors::AllowedOrigins::all();
    let cors = rocket_cors::CorsOptions {
        allowed_origins,
        allowed_methods: vec![Method::Get, Method::Post, Method::Put]
            .into_iter()
            .map(From::from)
            .collect(),
        allowed_headers: rocket_cors::AllowedHeaders::some(&[
            "Authorization",
            "Accept",
            "Content-Type",
        ]),
        ..Default::default()
    }
    .to_cors()?;

    rocket::ignite()
        .mount(
            "/",
            routes![
                list_files,
                list_files_in_source,
                move_file,
                login,
                list_sources,
                list_destinations,
            ],
        )
        .attach(cors)
        .attach(AdHoc::on_attach("File Config", |rocket| {
            let config = rocket
                .config()
                .get_str("file_config")
                .unwrap_or("file_config.toml")
                .to_string();
            match parse_config(&config) {
                Ok(config) => match validate_destinations(&config.destinations, &config.actions) {
                    Ok(_) => Ok(rocket
                        .manage(Sources {
                            sources: config.sources,
                        })
                        .manage(Destinations {
                            destinations: config.destinations,
                            actions: config.actions,
                        })
                        .manage(Users {
                            users: config.users,
                        })
                        .manage(Secret {
                            jwt_key: config.secret.as_bytes().to_owned(),
                            exp: config.expiry,
                        })),
                    Err(_) => Err(rocket),
                },
                Err(_) => Err(rocket),
            }
        }))
        .launch();

    Ok(())
}
