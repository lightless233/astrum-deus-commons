use std::collections::HashMap;

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


/// Package 输出用的结构体
#[derive(Debug, Serialize)]
pub struct PackageStdoutResult {
    success: bool,
    result_path: Option<String>,
    error: Option<String>,
}

impl PackageStdoutResult {
    pub fn ok(result_path: impl Into<String>) {
        let s = Self {
            success: true,
            result_path: Some(result_path.into()),
            error: None,
        };

        println!("{}", serde_json::to_string(&s).unwrap());
    }

    pub fn err(error: impl Into<String>) {
        let s = Self {
            success: false,
            result_path: None,
            error: Some(error.into()),
        };

        println!("{}", serde_json::to_string(&s).unwrap());
    }
}

/// Package 的输入相关
#[derive(Debug, Deserialize)]
pub struct PackageArgs {
    target: String,
    task_id: String,
    params: HashMap<String, String>,
}