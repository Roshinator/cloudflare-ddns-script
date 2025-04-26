use std::{net::Ipv4Addr, net::Ipv6Addr, path};
use clap::Parser;
use serde::{Serialize, Deserialize};
use reqwest::header;
use cloudflare::{endpoints::dns::dns::{self, DnsRecord}, framework::{auth::Credentials, client as cf_client, Environment}};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args
{
    #[arg(long)]
    config: path::PathBuf,

    #[arg(long)]
    generate: bool
}

#[derive(Deserialize, Serialize, Debug)]
struct CloudflareAuth
{
    email: String,
    api_key: String,
    zone_id: String
}

#[derive(Deserialize, Serialize, Debug)]
struct Config
{
    domains: Vec<String>,
    enable_ipv6: bool,
    cloudflare_info: CloudflareAuth
}


fn main() 
{
    let args = Args::parse();
    if args.generate
    {
        generate_config(args.config_path);
    }
    else
    {
        update_records(args.config_path);
    }
    
}

fn update_records(config_path: path::PathBuf)
{
    let config_file_data = std::fs::read_to_string(config_path).expect("Could not read config file");
    let config = toml::from_str::<Config>(&config_file_data).expect("Could not parse config file");

    let credentials = Credentials::UserAuthKey { email: config.cloudflare_info.email, key: config.cloudflare_info.api_key };
    let cf_api = cf_client::blocking_api::HttpApiClient::new(credentials, cf_client::ClientConfig::default(), Environment::Production)
        .expect("Could not initialize cloudflare api client");

    let list_request = dns::ListDnsRecords
    {
        zone_identifier: &config.cloudflare_info.zone_id,
        params: dns::ListDnsRecordsParams
        {
            direction: Some(cloudflare::framework::OrderDirection::Ascending),
            ..Default::default()
        }
    };
    let response = cf_api.request(&list_request).expect("Could not get existing DNS records");
    let dns_list = response.result;
    if dns_list.len() == 0
    {
        panic!("No dns items found");
    }

    update_ipv4(&config.domains, &dns_list, &config.cloudflare_info.zone_id, &cf_api);

    if config.enable_ipv6
    {
        update_ipv6(&config.domains, &dns_list, &config.cloudflare_info.zone_id, &cf_api);
    }
}

fn update_ipv4(domains: &Vec<String>, dns_list: &Vec<DnsRecord>, zone_id: &str, cf_client: &cf_client::blocking_api::HttpApiClient)
{
    let ipv4_addr_result = reqwest::blocking::get("https://ipv4.icanhazip.com");
    let Ok(ipv4_addr_response) = ipv4_addr_result else
    {
        println!("Request to get ipv4 address failed");
        return;
    };
    let Ok(ipv4_addr_text) = ipv4_addr_response.text() else
    {
        println!("Failed to convert ipv4 address response to text");
        return;
    };
    println!("External IP (v4): {}", ipv4_addr_text.trim());
    let Ok(ipv4_addr) = ipv4_addr_text.trim().parse::<Ipv4Addr>() else
    {
        println!("Failed to parse ipv4 response to an address");
        return;
    };
    for domain in domains
    {
        //find the ID of the dns record
        let mut current_ipv4_addr = Ipv4Addr::UNSPECIFIED;
        let dns_record_result = dns_list.iter().find(|&record|
            {
                if let dns::DnsContent::A{content} = record.content
                {
                    if record.name == *domain
                    {
                        current_ipv4_addr = content;
                        return true;
                    }
                }
                return false;
            });
        let Some(dns_record) = dns_record_result else
        {
            println!("No existing DNS A record found for {}, please create it", domain);
            continue;
        };
        if current_ipv4_addr == ipv4_addr
        {
            println!("DNS hasn't changed from existing record for {}, skipping...", domain);
            continue;
        }

        //Request update
        let update_request = dns::UpdateDnsRecord
        {
            zone_identifier: zone_id,
            identifier: &dns_record.id,
            params: dns::UpdateDnsRecordParams
            {
                ttl: None,
                proxied: None,
                name: &dns_record.name,
                content: dns::DnsContent::A { content: ipv4_addr }
            }
        };
        let response_result = cf_client.request(&update_request);
        let Ok(_) = response_result else 
        {
            println!("Failed to send update request for {}", domain);
            continue;
        };
        println!("DNS update success for {}", domain);
    }
}

fn update_ipv6(domains: &Vec<String>, dns_list: &Vec<DnsRecord>, zone_id: &str, cf_client: &cf_client::blocking_api::HttpApiClient)
{
    let ipv6_addr_result = reqwest::blocking::get("https://ipv6.icanhazip.com");
    let Ok(ipv6_addr_response) = ipv6_addr_result else
    {
        println!("Request to get ipv6 address failed");
        return;
    };
    let Ok(ipv6_addr_text) = ipv6_addr_response.text() else
    {
        println!("Failed to convert ipv6 address response to text");
        return;
    };
    println!("External IP (v6): {}", ipv6_addr_text.trim());
    let Ok(ipv6_addr) = ipv6_addr_text.trim().parse::<Ipv6Addr>() else
    {
        println!("Failed to parse ipv4 response to an address");
        return;
    };
    for domain in domains
    {
        //find the ID of the dns record
        let mut current_ipv6_addr = Ipv6Addr::UNSPECIFIED;
        let dns_record_result = dns_list.iter().find(|&record|
            {
                if let dns::DnsContent::AAAA{content} = record.content
                {
                    if record.name == *domain
                    {
                        current_ipv6_addr = content;
                        return true;
                    }
                }
                return false;
            });
        let Some(dns_record) = dns_record_result else
        {
            println!("No existing DNS AAAA record found for {}, please create it", domain);
            continue;
        };
        if current_ipv6_addr == ipv6_addr
        {
            println!("DNS hasn't changed from existing record for {}, skipping...", domain);
            continue;
        }

        //Request update
        let update_request = dns::UpdateDnsRecord
        {
            zone_identifier: zone_id,
            identifier: &dns_record.id,
            params: dns::UpdateDnsRecordParams
            {
                ttl: None,
                proxied: None,
                name: &dns_record.name,
                content: dns::DnsContent::AAAA { content: ipv6_addr }
            }
        };
        let response_result = cf_client.request(&update_request);
        let Ok(_) = response_result else 
        {
            println!("Failed to send update request for {}", domain);
            continue;
        };
        println!("DNS update success for {}", domain);
    }
}

fn generate_config(config_path: path::PathBuf)
{
    let example_auth = CloudflareAuth
    {
        email: "example@example.com".to_string(),
        api_key: "THISISAVERYLONGKEY".to_string(),
        zone_id: "ABIGLONGZONEID".to_string()
    };
    let example_config = Config
    {
        domains: vec!["example.com".to_string(), "subdomain.example.com".to_string()],
        enable_ipv6: false,
        cloudflare_info: example_auth
    };
    let toml = toml::to_string_pretty(&example_config)
        .expect("Failed to convert config to toml");
    std::fs::write(config_path, toml).expect("Failed to write to file, does its directory exist?");
}