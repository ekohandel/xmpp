use std::fmt::Debug;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::net::{Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream};
use std::str::FromStr;
use trust_dns::client::{Client, SyncClient};
use trust_dns::op::DnsResponse;
use trust_dns::rr::{DNSClass, Name, RData, RecordType};
use trust_dns::udp::UdpClientConnection;
use trust_dns_resolver::system_conf;

/// A trait used for any connection.
pub trait Connection: Read + Write + Debug {
    fn close(&mut self) -> Result<()>;
}

#[derive(Default)]
/// A connection configuration used for creating a connection.
pub struct ConnectionConfig {
    endpoint: Option<ConnectionEndpoint>,
}

enum ConnectionEndpoint {
    Domain(Name),
    Host(Name, u16),
    Addr(SocketAddr),
}

impl ConnectionConfig {
    pub fn new() -> Self {
        Default::default()
    }

    /// Create a [`ConnectionConfig`] based on just the domain [`Name`]. This
    /// should be use when automatic DNS SRV lookup is desired. The connection
    /// will be created against the FQDN returned from the DNS SRV lookup.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use xmpp::*;
    ///
    /// let conn_config = ConnectionConfig::new()
    ///                     .with_domain(Name::from_str("jabber.de").unwrap());
    /// ```
    /// [`Name`]: ../struct.Name.html
    /// [`ConnectionConfig`]: struct.ConnectionConfig.html
    pub fn with_domain(mut self, name: Name) -> Self {
        self.endpoint = Some(ConnectionEndpoint::Domain(name));
        self
    }

    /// Create a [`ConnectionConfig`] based on host [`Name`] and port. This
    /// should be use when automatic DNS SRV lookup is not desired. The
    /// connection will be created against the IP address returned by a DNS
    /// AAAA or A lookup.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use xmpp::*;
    ///
    /// let conn_config = ConnectionConfig::new()
    ///                     .with_host(Name::from_str("jabber.de").unwrap(),
    ///                                5222);
    /// ```
    /// [`Name`]: ../struct.Name.html
    /// [`ConnectionConfig`]: struct.ConnectionConfig.html
    pub fn with_host(mut self, name: Name, port: u16) -> Self {
        self.endpoint = Some(ConnectionEndpoint::Host(name, port));
        self
    }

    /// Create a [`ConnectionConfig`] based on a [`SocketAddr`]. This should
    /// be use when no DNS lookup is desired. The connection will be created
    /// against the given socket address.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use xmpp::*;
    /// use std::net::{Ipv4Addr, SocketAddrV4};
    ///
    /// // Create a socket address
    /// let ip = Ipv4Addr::new(10, 20, 30, 40);
    /// let addr = SocketAddr::V4(SocketAddrV4::new(ip, 1234));
    ///
    /// // Use the socket address to create a connection configuration 
    /// let conn_config = ConnectionConfig::new()
    ///                     .with_addr(addr);
    /// ```
    /// [`SocketAddr`]: ../enum.SocketAddr.html
    /// [`ConnectionConfig`]: struct.ConnectionConfig.html
    pub fn with_addr(mut self, addr: SocketAddr) -> Self {
        self.endpoint = Some(ConnectionEndpoint::Addr(addr));
        self
    }

    /// Create a [`Connection`] based on a [`ConnectionConfig`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use xmpp::*;
    ///
    /// // Create a connection based on a domain name
    /// let conn = ConnectionConfig::new()
    ///                 .with_domain(Name::from_str("jabber.de").unwrap())
    ///                 .create_connection();
    /// 
    /// // Create a connection based on a host
    /// let conn = ConnectionConfig::new()
    ///                 .with_host(Name::from_str("jabber.de").unwrap(), 5222)
    ///                 .create_connection();
    /// ```
    /// [`Connection`]: trait.Connection.html
    /// [`ConnectionConfig`]: struct.ConnectionConfig.html
    pub fn create_connection(self) -> Result<Box<Connection>> {
        TcpConnection::new_with_config(self)
    }
}

/// A TCP [`Connection`] for communication use. The easiest way to create a
/// [`Connection`] is to use [`ConnectionConfig`].
/// 
/// # Example
/// 
/// ```no_run
/// use xmpp::*;
///
/// // Create a connection based on a domain name
/// let conn = ConnectionConfig::new()
///                 .with_domain(Name::from_str("jabber.de").unwrap())
///                 .create_connection();
/// 
/// // Create a connection based on a host
/// let conn = ConnectionConfig::new()
///                 .with_host(Name::from_str("jabber.de").unwrap(), 5222)
///                 .create_connection();
/// ```
/// [`Connection`]: trait.Connection.html
/// [`ConnectionConfig`]: struct.ConnectionConfig.html
#[derive(Debug)]
pub struct TcpConnection {
    conn: TcpStream,
}

impl TcpConnection {
    /// Create a [`Connection`] based on a [`ConnectionConfig`]. This specific
    /// implementation of [`Connection`] will use the TCP protocol.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use xmpp::*;
    ///
    /// // Create a connection configuration
    /// let conn_config = ConnectionConfig::new()
    ///                     .with_domain(Name::from_str("jabber.de").unwrap());
    /// 
    /// // Use the configuration to create an actual connection
    /// let conn = TcpConnection::new_with_config(conn_config);
    /// ```
    /// [`Connection`]: trait.Connection.html
    /// [`ConnectionConfig`]: struct.ConnectionConfig.html
    pub fn new_with_config(config: ConnectionConfig) -> Result<Box<Connection>> {
        if config.endpoint.is_none() {
            return Err(ErrorKind::InvalidInput.into());
        }

        match config.endpoint.unwrap() {
            ConnectionEndpoint::Addr(addr) => TcpConnection::new_from_addr(addr),
            ConnectionEndpoint::Host(name, port) => TcpConnection::new_from_host(&name, port),
            ConnectionEndpoint::Domain(name) => TcpConnection::new_from_domain(&name),
        }
    }

    fn new_from_addr(addr: SocketAddr) -> Result<Box<Connection>> {
        Ok(Box::new(TcpConnection {
            conn: TcpStream::connect(addr)?,
        }))
    }

    fn new_from_host(name: &Name, port: u16) -> Result<Box<Connection>> {
        // Perform the DNS AAAA (IPv6) lookup and attempt to connect to
        // the returned resources
        if let Ok(records) = TcpConnection::execute_lookup(name, RecordType::AAAA) {
            for record in &records {
                if let RData::AAAA(ip) = record {
                    // Return the first successful connection
                    if let Ok(conn) = TcpConnection::new_from_addr(SocketAddr::from(
                        SocketAddrV6::new(*ip, port, 0, 0),
                    )) {
                        return Ok(conn);
                    }
                }
            }
        }

        // Perform the DNS A (IPv4) lookup and attempt to connect to
        // the returned resources
        if let Ok(records) = TcpConnection::execute_lookup(name, RecordType::A) {
            for record in &records {
                if let RData::A(ip) = record {
                    // Return the first successful connection
                    if let Ok(conn) =
                        TcpConnection::new_from_addr(SocketAddr::from(SocketAddrV4::new(*ip, port)))
                    {
                        return Ok(conn);
                    }
                }
            }
        }

        Err(Error::from(ErrorKind::NotConnected))
    }

    fn new_from_domain(name: &Name) -> Result<Box<Connection>> {
        // Construct the DNS SRV query
        let query = Name::from_str("_xmpp-client._tcp")
            .unwrap()
            .append_domain(name);

        // Perform the DNS SRV lookup and attempt to connect to the returned resources
        if let Ok(records) = TcpConnection::execute_lookup(&query, RecordType::SRV) {
            for record in &records {
                if let RData::SRV(srv) = record {
                    // This condition "means that the service is decidedly not
                    // available at this domain".
                    if srv.target().is_root() && records.len() == 1 {
                        return Err(Error::from(ErrorKind::NotConnected))
                    }

                    // Return the first successful connection
                    if let Ok(conn) = TcpConnection::new_from_host(srv.target(), srv.port()) {
                        return Ok(conn);
                    }
                }
            }
        }

        // Initiate the fallback process
        TcpConnection::new_from_host(name, 5222)
    }

    fn execute_lookup(name: &Name, record_type: RecordType) -> Result<Vec<RData>> {
        let (config, _) = system_conf::read_system_conf()?;

        if config.name_servers().is_empty() {
            return Err(Error::from(ErrorKind::NotFound));
        }

        let name_server = config.name_servers()[0].socket_addr;
        let client = SyncClient::new(UdpClientConnection::new(name_server)?);
        let response: DnsResponse = client.query(name, DNSClass::IN, record_type)?;

        Ok(response
            .answers()
            .iter()
            .filter(|record| record.record_type() == record_type)
            .map(|record| record.rdata().to_owned())
            .collect())
    }
}

impl Connection for TcpConnection {
    fn close(&mut self) -> Result<()> {
        self.conn.shutdown(Shutdown::Both)
    }
}

impl Read for TcpConnection {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.conn.read(buf)
    }
}

impl Write for TcpConnection {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.conn.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.conn.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_domain() {
        ConnectionConfig::new()
            .with_domain(Name::from_str("jabber.de").unwrap())
            .create_connection()
            .unwrap();

        ConnectionConfig::new()
            .with_domain(Name::from_str("jabber.d").unwrap())
            .create_connection()
            .expect_err("Invalid domain.");
    }

    #[test]
    fn test_with_host() {
        ConnectionConfig::new()
            .with_host(Name::from_str("jabber.de").unwrap(), 5222)
            .create_connection()
            .unwrap();

        ConnectionConfig::new()
            .with_host(Name::from_str("jabber.d").unwrap(), 5222)
            .create_connection()
            .expect_err("Invalid domain.");
    }
}
