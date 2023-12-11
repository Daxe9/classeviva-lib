use crate::types::*;
use reqwest::{header::HeaderMap, Client};
use anyhow::{Result, bail};

const BASE_URL: &str = "https://web.spaggiari.eu/rest/v1";

fn get_header_map() -> HeaderMap {
    let mut map = HeaderMap::new();
    map.insert("Content-Type", "application/json".parse().unwrap());
    map.insert("Z-Dev-ApiKey", "Tg1NWEwNGIgIC0K".parse().unwrap());
    map.insert("User-Agent", "CVVS/std/4.1.7 Android/10".parse().unwrap());
    map
}

pub async fn login(username: String, password: String) -> Result<TokenCredential> {
    let login_data = LoginData::new(Credentials { username, password });

    // Initialize the reqwest client for api call
    let client = Client::new();
    // Get result as string form from the server
    let raw_result = match client
        .post(format!("{}/auth/login", BASE_URL))
        .headers(get_header_map())
        .json(&login_data)
        .send()
        .await
    {
        Ok(v) => v,
        Err(e) => bail!("Unable to send login request {}", e),
    };

    let mut token_credential = TokenCredential {
        token: String::new(),
        tokenAP: String::new(),
        studentId: String::new(),
    };

    match raw_result.json::<LoginResponse>().await {
        Ok(res) => {
            match res {
                LoginResponse::LoginPayload(v) => {
                    token_credential.token = v.token;
                    token_credential.tokenAP = v.tokenAP;
                    // remove the first and the last character from the ident field to obtain the studentId
                    token_credential.studentId = v.ident[1..v.ident.len() - 1].to_string();
                    return Ok(token_credential);
                }
                LoginResponse::LoginError(_) => {
                    bail!("Login request failed")
                }
            }
        }
        Err(e) => {
            bail!("Parsing login response: {}", e)
        }
    }
}

fn process_url(url: &str, student_id: &str) -> String {
    url.replace("<studentID>", student_id)
}

async fn get_request_wrapper(url: String, credentials: TokenCredential) -> Result<String> {
    let url = process_url(&url, &credentials.studentId);
    let client = Client::new();
    let raw_result = match client
        .get(&url)
        .headers(get_header_map())
        .header("z-auth-token", credentials.token)
        .send()
        .await
    {
        Ok(v) => v,
        Err(e) => bail!("Unable to send request at {} {}", url, e),
    };

    match raw_result.text().await {
        Ok(v) => Ok(v),
        Err(e) => bail!("Unable to parse response {}", e),
    }
}

/// Get the list of absences from the specified user
///
/// * `credentails` - The credentials of the user
pub async fn absence_request(credentials: TokenCredential) -> Result<Absences> {
    let url = format!("{}/students/<studentID>/absences/details", BASE_URL);
    let raw_result = get_request_wrapper(url, credentials).await?;

    match serde_json::from_str(&raw_result) {
        Err(e) => {
            bail!("Parsing absence response {}", e);
        },
        Ok(v) => {
            match v {
                ResponseResult::Absences(payload) => {
                    return Ok(payload);
                }
                ResponseResult::ExpiredToken(_) => {
                    bail!("Expired Token")
                }
                _ => {
                    bail!("Wrong return type upon api call {}", raw_result);
                }
            }
        }
    };
}


/// Get the list of grades from the specified user
///
/// * `credentails` - The credentials of the user
pub async fn grade_request(credentials: TokenCredential) -> Result<Grades> {
    let url = format!("{}/students/<studentID>/grades", BASE_URL);
    let raw_result = get_request_wrapper(url, credentials).await?;
    // println!("{}", raw_result);

    match serde_json::from_str(&raw_result) {
        Err(e) => {
            bail!("Parsing grade response: {}", e);
        },
        Ok(v) => {
            match v {
                ResponseResult::Grades(payload) => {
                    return Ok(payload);
                }
                ResponseResult::ExpiredToken(_) => {
                    bail!("Expired Token")
                }
                _ => {
                    bail!("Wrong return type upon api call {}", raw_result);
                }
            }
        }
    };
}


/// Get the list of assignments and notifications of the specified user from the start date to the
/// end date
/// 
/// * `credentails` - The credentials of the user
/// * `start_date` - The start date of the period specified in YYYYMMDD form
/// * `end_date` - The end date of the period specified in YYYYMMDD form 
pub async fn agenda_request(credentials: TokenCredential, start_date: String, end_date: String) -> Result<Agendas> {
    let url = format!("{}/students/<studentID>/agenda/all/{}/{}", BASE_URL, start_date, end_date);
    let raw_result = get_request_wrapper(url, credentials).await?;

    match serde_json::from_str(&raw_result) {
        Err(e) => {
            bail!("Parsing agenda response {}", e);
        },
        Ok(v) => {
            match v {
                ResponseResult::Agendas(payload) => {
                    return Ok(payload);
                }
                ResponseResult::ExpiredToken(_) => {
                    bail!("Expired Token")
                }
                _ => {
                    bail!("Wrong return type upon api call {}", raw_result);
                }
            }
        }
    };
}


/// Get the list of lessons' topic of the specified user from the start date to the
/// end date
/// 
/// * `credentails` - The credentials of the user
/// * `start_date` - The start date of the period specified in YYYYMMDD form
/// * `end_date` - The end date of the period specified in YYYYMMDD form 
pub async fn lesson_request(credentials: TokenCredential, start_date: String, end_date: String) -> Result<Lessons> {
    let url = format!("{}/students/<studentID>/lessons/{}/{}", BASE_URL, start_date, end_date);
    let raw_result = get_request_wrapper(url, credentials).await?;

    match serde_json::from_str(&raw_result) {
        Err(e) => {
            bail!("Parsing lesson response {}", e);
        },
        Ok(v) => {
            match v {
                ResponseResult::Lessons(payload) => {
                    return Ok(payload);
                }
                ResponseResult::ExpiredToken(_) => {
                    bail!("Expired Token")
                }
                _ => {
                    bail!("Wrong return type upon api call {}", raw_result);
                }
            }
        }
    };
}
