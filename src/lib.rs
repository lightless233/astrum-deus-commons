use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ScanResult {
    pub port: Vec<PortResultItem>,
    
    // 以下字段尚未用到
    pub vulns: Vec<VulnResultItem>,
    pub domain: Vec<DomainResultItem>,
    pub dir: Vec<DirResultItem>,
}

/// 端口扫描的结果对应的结构体
#[derive(Debug, Serialize, Deserialize)]
pub struct PortResultItem {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    // 指纹、banner信息
    pub banner: Option<String>,
    pub extra: Option<String>,
}

/// 域名扫描结果对应的结构体
#[derive(Debug, Serialize, Deserialize)]
pub struct DomainResultItem {
    pub domain: String,
    pub record_type: String,
    pub record: String,
    pub status_code: Option<u16>,
    pub title: Option<String>,
    pub content: Option<String>,
    pub screenshot: Option<String>,
    pub extra: Option<String>,
}

/// 目录扫描的结果对应的结构体
#[derive(Debug, Serialize, Deserialize)]
pub struct DirResultItem {
    pub path: String,
    pub status_code: u16,
    pub method: String,
    pub title: Option<String>,
    pub content: Option<String>,
    pub screenshot: Option<String>,
    pub extra: Option<String>,
}

/// 漏洞扫描结果对应的结构体
#[derive(Debug, Serialize, Deserialize)]
pub struct VulnResultItem {
    pub title: String,
    pub url: String,
    pub description: String,
}
