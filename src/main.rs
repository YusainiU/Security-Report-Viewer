use axum::{extract::{DefaultBodyLimit, Multipart, Path}, http::StatusCode, response::Html, routing::{get,post}, Router, Json};
use serde::Serialize;
use std::{collections::BTreeMap, net::IpAddr, path::PathBuf, fs, os::unix::fs::{DirBuilderExt, PermissionsExt, OpenOptionsExt}, sync::Mutex};
#[derive(Serialize,Default)]
struct Report { title:String, source:String, inputs:BTreeMap<String,u64>, ips:Vec<Threat>, sections:Vec<Section>, warnings:Vec<String> }
#[derive(Serialize)]
struct Threat { ip:IpAddr, severity:String, counts:BTreeMap<String,u64> }
#[derive(Serialize)]
struct Section { title:String, count:Option<u64>, lines:Vec<String> }
const FIELDS:[&str;15]=["probes","SQL","sensitive","XSS/traversal","suspicious_2xx","suspicious_5xx","suspicious_403/404","other_status","SSH_fail","SSH_ok","SSH_ok_after_failure_in_input","HTTP_total","HTTP_403/404","HTTP_5xx","firewall"];
fn parse(raw:&str)->Result<Report,String>{
 let decoded;
 let raw=if raw.trim_start().starts_with('{') {
 let value:serde_json::Value=serde_json::from_str(raw).map_err(|e|e.to_string())?;
 if value["schema_version"].as_u64()!=Some(3){return Err("Unsupported JSON schema".into())}
 decoded=value["report_text"].as_str().ok_or("Missing report_text")?.to_owned();
 decoded.as_str()
 }else{raw};
 let mut r=Report::default(); let mut lines=raw.lines();
 let first=lines.next().unwrap_or("").trim_start_matches('\u{feff}');
 if !first.starts_with("SECURITY LOG SCAN v2.0") && !first.starts_with("SECURITY LOG SCAN v3.0") {return Err("Expected a v2 or v3 scanner report header.".into())} r.title=first.into();
 let mut correlated=false;
 for line in lines { let line=line.trim(); if line.is_empty(){continue}
 if let Some(s)=line.strip_prefix("Source: "){r.source=s.into();continue}
 if let Some((k,v))=line.split_once(" input lines:"){if let Ok(n)=v.trim().parse(){r.inputs.insert(k.into(),n);continue}}
 if let Some(s)=line.strip_prefix("=== ").and_then(|s|s.strip_suffix(" ===")){if s=="Correlated threat analysis by IP"{correlated=true} r.sections.push(Section{title:s.into(),count:None,lines:vec![]});continue}
 if let Some(section)=r.sections.last_mut(){
 if let Some(n)=line.strip_prefix("Matching lines: "){section.count=n.parse().ok();continue}
 if section.title=="Correlated threat analysis by IP" {
 let mut parts=line.split_whitespace(); let severity=parts.next().unwrap_or("");
 if matches!(severity,"INFO"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL") {
 let ip=parts.next().and_then(|s|s.strip_prefix("IP=")).and_then(|s|s.parse::<IpAddr>().ok());
 let counts:BTreeMap<String,u64>=parts.filter_map(|s|{let(k,v)=s.split_once('=')?;Some((k.into(),v.parse().ok()?))}).collect();
 if let Some(ip)=ip {if FIELDS.iter().all(|k|counts.contains_key(*k)){r.ips.push(Threat{ip,severity:severity.into(),counts});continue}}
 r.warnings.push("A malformed correlated IP row was retained as evidence.".into());
 }} section.lines.push(line.into());
 }}
 if !correlated{return Err("Missing correlated threat analysis section.".into())}
 if !r.sections.iter().any(|s|s.title=="Malware detection records" && s.count.is_some()){r.warnings.push("Malware section missing or incomplete; status unknown.".into())}
 if let Some(s)=r.sections.iter().find(|s|s.title=="Scan coverage and metadata"){
 if let Ok(m)=serde_json::from_str::<serde_json::Value>(&s.lines.join("\n")){
 if m["scan_status"]!="complete"{r.warnings.push("Partial scan: review log coverage and metadata.".into());}
 }else{r.warnings.push("Invalid scan coverage metadata.".into());}
 }
 Ok(r)
}
async fn upload(mut m:Multipart)->Result<Json<Report>,(StatusCode,String)>{
 while let Some(f)=m.next_field().await.map_err(|e|(StatusCode::BAD_REQUEST,e.to_string()))? {if f.name()!=Some("report"){continue} let b=f.bytes().await.map_err(|e|(StatusCode::BAD_REQUEST,e.to_string()))?; let s=String::from_utf8_lossy(&b);return parse(&s).map(Json).map_err(|e|(StatusCode::UNPROCESSABLE_ENTITY,e))} Err((StatusCode::BAD_REQUEST,"Select a report file.".into()))
}
type ApiError = (StatusCode,String);
static SCAN_LOCK: Mutex<()> = Mutex::new(());
fn err(e: impl std::fmt::Display) -> ApiError { (StatusCode::INTERNAL_SERVER_ERROR,e.to_string()) }
fn store() -> Result<PathBuf,ApiError> {
 let dir=std::env::current_dir().map_err(err)?.join("reports");
 if !dir.exists(){fs::DirBuilder::new().mode(0o700).create(&dir).map_err(err)?;}
 let meta=fs::symlink_metadata(&dir).map_err(err)?;
 if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {return Err(err("reports must be a private directory (chmod 700 reports)"));}
 Ok(dir)
}
fn valid_name(n:&str)->bool { n.starts_with("security-report-") && n.ends_with(".txt") && n.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'.') }
async fn saved()->Result<Json<Vec<String>>,ApiError>{
 let mut names=vec![];for entry in fs::read_dir(store()?).map_err(err)? {let e=entry.map_err(err)?;let n=e.file_name().to_string_lossy().into_owned();if valid_name(&n)&&e.file_type().map_err(err)?.is_file(){names.push(n)}} names.sort_by(|a,b|b.cmp(a));Ok(Json(names))
}
fn read_saved(n:&str)->Result<Report,ApiError>{
 if !valid_name(n){return Err((StatusCode::BAD_REQUEST,"Invalid report name".into()))}let p=store()?.join(n);let m=fs::symlink_metadata(&p).map_err(err)?;if !m.is_file()||m.len()>10*1024*1024{return Err(err("Invalid or oversized report"))}parse(&fs::read_to_string(p).map_err(err)?).map_err(err)
}
async fn open_saved(Path(n):Path<String>)->Result<Json<Report>,ApiError>{read_saved(&n).map(Json)}
fn delete_report(dir: &std::path::Path, name: &str) -> Result<(), ApiError> {
 if !valid_name(name) { return Err((StatusCode::BAD_REQUEST, "Invalid report name".into())); }
 let path = dir.join(name);
 let map_error = |e: std::io::Error| if e.kind() == std::io::ErrorKind::NotFound {
 (StatusCode::NOT_FOUND, "Report not found".into())
 } else { err(e) };
 let metadata = fs::symlink_metadata(&path).map_err(map_error)?;
 if !metadata.is_file() { return Err((StatusCode::BAD_REQUEST, "Not a regular report file".into())); }
 fs::remove_file(path).map_err(map_error)
}
async fn delete_saved(headers: axum::http::HeaderMap, Path(name): Path<String>) -> Result<StatusCode, ApiError> {
 if headers.get("x-local-scan").and_then(|v| v.to_str().ok()) != Some("1") {
 return Err((StatusCode::FORBIDDEN, "Use the local dashboard to delete reports".into()));
 }
 let _guard = SCAN_LOCK.try_lock().map_err(|_| (StatusCode::CONFLICT, "A scan is running; try again later".into()))?;
 delete_report(&store()?, &name)?;
 Ok(StatusCode::NO_CONTENT)
}
#[derive(Serialize)] struct ScanResult {name:String, report:Report, warning:String}
async fn scan(headers:axum::http::HeaderMap)->Result<Json<ScanResult>,ApiError>{
 if headers.get("x-local-scan").and_then(|v|v.to_str().ok())!=Some("1"){return Err((StatusCode::FORBIDDEN,"Use the local dashboard to run scans".into()))}
 tokio::task::spawn_blocking(||{
 let _guard=SCAN_LOCK.try_lock().map_err(|_|(StatusCode::CONFLICT,"A scan is already running".into()))?;
 let dir=store()?;let temp=tempfile::Builder::new().prefix("scan-").tempdir_in(&dir).map_err(err)?;
 let script=temp.path().join("scanner.sh");fs::write(&script,include_str!("../security-log-scan-v3.sh")).map_err(err)?;
 let output=std::process::Command::new("/usr/bin/timeout").args(["--kill-after=5s","300s","/bin/bash"]).arg(&script).args(["--format","text"]).current_dir(temp.path()).env_clear().env("PATH","/usr/bin:/bin").env("THRESHOLD",std::env::var("THRESHOLD").unwrap_or_else(|_|"20".into())).env("LOG_ROOT",std::env::var("LOG_ROOT").unwrap_or_else(|_|"/var/log".into())).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped()).output().map_err(err)?;
 if !output.status.success(){return Err(err(format!("Scan failed: {}",output.status)))}
 let entry=fs::read_dir(temp.path()).map_err(err)?.filter_map(Result::ok).find(|e|valid_name(&e.file_name().to_string_lossy())).ok_or_else(||err("Scanner produced no report"))?;
 let name=entry.file_name().to_string_lossy().into_owned();let p=entry.path();if fs::metadata(&p).map_err(err)?.len()>10*1024*1024{return Err(err("Generated report exceeds 10 MiB"))}let raw=fs::read_to_string(&p).map_err(err)?;let report=parse(&raw).map_err(err)?;
 let warning=if output.stderr.is_empty(){String::new()}else{"Scanner reported diagnostics; log coverage may be incomplete. Check log permissions.".into()};
 let mut report=report;if !warning.is_empty(){report.warnings.push(warning.clone());}let raw=if warning.is_empty(){raw}else{format!("{}\n=== Scan diagnostics ===\n{}\n",raw,warning)};use std::io::Write;let mut f=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(dir.join(&name)).map_err(err)?;f.write_all(raw.as_bytes()).map_err(err)?;Ok(Json(ScanResult{name,report,warning}))
 }).await.map_err(err)?
}
async fn download_scanner() -> impl axum::response::IntoResponse {
 ([(axum::http::header::CONTENT_TYPE,"application/octet-stream"),(axum::http::header::CONTENT_DISPOSITION,"attachment; filename=\"security-log-scan-v3.sh\""),(axum::http::header::X_CONTENT_TYPE_OPTIONS,"nosniff")],include_str!("../security-log-scan-v3.sh"))
}
fn parse_port(value:&str)->Result<u16,String>{
 value.parse::<u16>().ok().filter(|port|*port!=0).ok_or_else(||"APP_PORT must be an integer from 1 to 65535".into())
}
#[cfg(test)] mod port_tests {
 use super::*;
 #[test] fn valid_ports(){assert_eq!(parse_port("8080"),Ok(8080));assert_eq!(parse_port("9080"),Ok(9080));assert_eq!(parse_port("65535"),Ok(65535));}
 #[test] fn invalid_ports(){for value in ["","0","65536","-1","abc"," 8080"]{assert!(parse_port(value).is_err());}}
}
#[tokio::main] async fn main(){if std::process::Command::new("id").arg("-u").output().map(|o|o.stdout==b"0\n").unwrap_or(true){eprintln!("ERROR: Run as an unprivileged user, not root");std::process::exit(1)} let app=Router::new().route("/",get(||async{Html(include_str!("../index.html"))})).route("/download/scanner",get(download_scanner)).route("/parse",post(upload)).route("/scan",post(scan)).route("/reports",get(saved)).route("/reports/{name}",get(open_saved).delete(delete_saved)).layer(DefaultBodyLimit::max(10*1024*1024));let port=match std::env::var("APP_PORT") {
 Ok(value)=>match parse_port(&value){Ok(port)=>port,Err(message)=>{eprintln!("ERROR: {message}");std::process::exit(1)}},
 Err(std::env::VarError::NotPresent)=>8080,
 Err(e)=>{eprintln!("ERROR: Cannot read APP_PORT: {e}");std::process::exit(1)}
 };
 let listener=match tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,port)).await {
 Ok(listener)=>listener,
 Err(e)=>{eprintln!("ERROR: Cannot bind 127.0.0.1:{port}: {e}");if e.kind()==std::io::ErrorKind::AddrInUse{eprintln!("Port {port} is already in use. Choose a free port using APP_PORT, e.g. APP_PORT=9080 ./security-report-viewer");}std::process::exit(1)}
 };
 println!("Security Report Viewer: http://127.0.0.1:{port}");
 if let Err(e)=axum::serve(listener,app).await{eprintln!("ERROR: Server failed: {e}");std::process::exit(1)}}
#[cfg(test)] mod tests{use super::*;#[test]fn invalid(){assert!(parse("hello").is_err());}#[test]fn fixture(){let r=parse(include_str!("../sample-report.txt")).unwrap();assert_eq!(r.ips.len(),2);assert_eq!(r.ips[0].counts["suspicious_2xx"],1);assert_eq!(r.ips[1].ip.to_string(),"80.66.83.67");}}

#[cfg(test)] mod deletion_tests {
 use super::*;
 #[test] fn deletes_only_selected_report() {
 let dir=tempfile::tempdir().unwrap();
 let name="security-report-test.txt";
 fs::write(dir.path().join(name),"report").unwrap();
 fs::write(dir.path().join("other.txt"),"keep").unwrap();
 assert!(delete_report(dir.path(),name).is_ok());
 assert!(!dir.path().join(name).exists());
 assert!(dir.path().join("other.txt").exists());
 assert_eq!(delete_report(dir.path(),name).unwrap_err().0,StatusCode::NOT_FOUND);
 assert_eq!(delete_report(dir.path(),"../other.txt").unwrap_err().0,StatusCode::BAD_REQUEST);
 }
 #[test] fn rejects_symlink() {
 let dir=tempfile::tempdir().unwrap();
 let target=dir.path().join("other.txt");
 fs::write(&target,"keep").unwrap();
 std::os::unix::fs::symlink(&target,dir.path().join("security-report-link.txt")).unwrap();
 assert_eq!(delete_report(dir.path(),"security-report-link.txt").unwrap_err().0,StatusCode::BAD_REQUEST);
 assert!(target.exists());
 }
}

