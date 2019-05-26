use crate::connection::Connection;
use std::io::{Error, Read, Write};
use std::io::{ErrorKind, Result};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream};
use std::str::FromStr;
use trust_dns::client::{Client, SyncClient};
use trust_dns::op::DnsResponse;
use trust_dns::rr::rdata::srv::SRV;
use trust_dns::rr::{DNSClass, Name, RData, RecordType};
use trust_dns::udp::UdpClientConnection;
use trust_dns_resolver::system_conf;

#[derive(Default, Debug)]
pub struct TcpConnector {
    origin_domain: Option<Name>,
    name_server: Option<SocketAddr>,
    service_server: Option<SocketAddr>,
    tcp_stream: Option<TcpStream>,
}

impl TcpConnector {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_origin_domain(mut self, origin_domain: Name) -> Self {
        self.origin_domain = Some(origin_domain);
        self
    }

    pub fn with_name_server(mut self, name_server: SocketAddr) -> Self {
        self.name_server = Some(name_server);
        self
    }

    pub fn build(mut self) -> Result<Box<dyn Connection>> {
        if self.origin_domain.is_none() {
            return Err(Error::from(ErrorKind::InvalidInput));
        }

        if self.name_server.is_none() {
            self.name_server = Some(self.get_default_name_server()?);
        }

        Ok(Box::new(self))
    }

    pub fn origin_domain(&self) -> Option<&Name> {
        self.origin_domain.as_ref().and_then(Some)
    }

    pub fn name_server(&self) -> Option<&SocketAddr> {
        self.name_server.as_ref().and_then(Some)
    }

    pub fn connect(&mut self) -> Result<()> {
        let name = Name::from_str(&format!(
            "_xmpp-client._tcp.{}",
            self.origin_domain
                .as_ref()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?
        ))?;

        let srv = self.execute_srv_lookup(&name)?;
        let port = srv.port();
        let name = srv.target();

        let ip = self.execute_ip_lookup(name)?;

        self.service_server = Some(SocketAddr::from(SocketAddrV4::new(ip, port)));

        self.tcp_stream = Some(TcpStream::connect(self.service_server.unwrap())?);

        Ok(())
    }

    fn get_default_name_server(&self) -> Result<SocketAddr> {
        let (config, _) = system_conf::read_system_conf()?;

        if !config.name_servers().is_empty() {
            return Ok(config.name_servers()[0].socket_addr);
        }

        Err(Error::from(ErrorKind::NotFound))
    }

    fn execute_ip_lookup(&self, name: &Name) -> Result<Ipv4Addr> {
        if let Ok(r) = self.execute_lookup(&name, RecordType::A) {
            if let RData::A(ip) = r {
                return Ok(ip);
            }
        }

        Err(Error::from(ErrorKind::NotFound))
    }

    fn execute_srv_lookup(&self, name: &Name) -> Result<SRV> {
        if let Ok(r) = self.execute_lookup(&name, RecordType::SRV) {
            if let RData::SRV(srv) = r {
                return Ok(srv);
            }
        }

        Err(Error::from(ErrorKind::NotFound))
    }

    fn execute_lookup(&self, name: &Name, record_type: RecordType) -> Result<RData> {
        let client = SyncClient::new(UdpClientConnection::new(self.name_server.unwrap()).unwrap());
        let response: DnsResponse = client.query(name, DNSClass::IN, record_type).unwrap();

        response
            .answers()
            .to_owned()
            .into_iter()
            .find(|rec| rec.rr_type() == record_type)
            .and_then(|rr| Some(rr.rdata().to_owned()))
            .ok_or_else(|| Error::from(ErrorKind::NotFound))
    }
}

impl Connection for TcpConnector {
    fn connect(&mut self) -> Result<()> {
        self.connect()
    }
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.tcp_stream
            .as_ref()
            .ok_or(ErrorKind::NotConnected)?
            .read(buf)
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.tcp_stream
            .as_ref()
            .ok_or(ErrorKind::NotConnected)?
            .write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.tcp_stream
            .as_ref()
            .ok_or(ErrorKind::NotConnected)?
            .flush()
    }

    fn close(&mut self) -> Result<()> {
        self.tcp_stream
            .as_ref()
            .ok_or(ErrorKind::NotConnected)?
            .shutdown(Shutdown::Both)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    #[test]
    fn test_origin_domain() {
        assert_eq!(
            TcpConnector::new()
                .with_origin_domain(Name::from_str("test.com").unwrap())
                .origin_domain()
                .unwrap()
                .to_ascii(),
            Name::from_str("test.com").unwrap().to_ascii()
        );
        assert_eq!(
            TcpConnector::new()
                .with_origin_domain(Name::from_str("test.com.").unwrap())
                .origin_domain()
                .unwrap()
                .to_ascii(),
            Name::from_str("test.com.").unwrap().to_ascii()
        );
    }

    #[test]
    fn test_name_server() {
        assert_eq!(
            TcpConnector::new()
                .with_name_server(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from_str("10.20.30.40").unwrap(),
                    50
                )))
                .name_server()
                .unwrap()
                .to_owned(),
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from_str("10.20.30.40").unwrap(),
                50
            ))
        )
    }

    #[test]
    fn test_build() {
        TcpConnector::new()
            .with_origin_domain(Name::from_str("jabber.de").unwrap())
            .build()
            .unwrap();

        TcpConnector::new()
            .with_origin_domain(Name::from_str("jabbder.d").unwrap())
            .build()
            .unwrap();
    }

    #[test]
    fn test_connection() {
        let mut conn = TcpConnector::new()
            .with_origin_domain(Name::from_str("jabber.de").unwrap())
            .build()
            .unwrap();
        conn.connect().unwrap();
        conn.close().unwrap();

        let mut conn = TcpConnector::new()
            .with_origin_domain(Name::from_str("canada.ca").unwrap())
            .build()
            .unwrap();
        conn.connect().expect_err("No service");
    }
}
