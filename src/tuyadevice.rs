//! # TuyaDevice
//! The TuyaDevice represents a communication channel with a Tuya compatible device. It
//! encapsulates the device key, version and ip address. By supplying a Payload to either set() or
//! get() functions the framework takes care of sending and receiving the reply from the device.
//!
//! The TuyaDevice is the high level device communication API. To get in to the nitty gritty
//! details, create a MessageParser.
use crate::error::ErrorKind;
use crate::mesparse::{CommandType, Message, MessageParser, TuyaVersion};
use crate::{Payload, Result};
use log::{debug, info};
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct TuyaDevice {
    mp: MessageParser,
    addr: SocketAddr,
    key: Option<String>,
    version: TuyaVersion,
}

impl TuyaDevice {
    pub fn create(ver: &str, key: Option<&str>, addr: IpAddr) -> Result<TuyaDevice> {
        let mp = MessageParser::create(ver, key)?;
        TuyaDevice::create_with_mp(mp, addr, key, ver)
    }

    pub fn create_with_mp(
        mp: MessageParser,
        addr: IpAddr,
        key: Option<&str>,
        ver: &str,
    ) -> Result<TuyaDevice> {
        let version = ver.parse()?;
        Ok(TuyaDevice {
            mp,
            addr: SocketAddr::new(addr, 6668),
            key: key.map(|k| k.to_string()),
            version,
        })
    }

    pub async fn set(&self, tuya_payload: Payload, seq_id: u32) -> Result<()> {
        let mes = Message::new(tuya_payload, CommandType::Control, Some(seq_id));
        let replies = self.send(&mes, seq_id).await?;
        replies
            .iter()
            .for_each(|mes| info!("Decoded response ({}):\n{}", seq_id, mes));
        Ok(())
    }

    pub async fn get(&self, tuya_payload: Payload, seq_id: u32) -> Result<Vec<Message>> {
        let mes = Message::new(tuya_payload, CommandType::DpQuery, Some(seq_id));
        let replies = self.send(&mes, seq_id).await?;
        replies
            .iter()
            .for_each(|mes| info!("Decoded response ({}):\n{}", seq_id, mes));
        Ok(replies)
    }

    pub async fn refresh(&self, tuya_payload: Payload, seq_id: u32) -> Result<Vec<Message>> {
        let mes = Message::new(tuya_payload, CommandType::DpRefresh, Some(seq_id));
        let replies = self.send(&mes, seq_id).await?;
        replies
            .iter()
            .for_each(|mes| info!("Decoded response ({}):\n{}", seq_id, mes));
        Ok(replies)
    }

    async fn send(&self, mes: &Message, seq_id: u32) -> Result<Vec<Message>> {
        let mut tcpstream = TcpStream::connect(&self.addr).await?;
        tcpstream.set_nodelay(true)?;

        // Protocol v3.4 requires session key negotiation
        if self.version == TuyaVersion::ThreeFour {
            let local_nonce = "0123456789abcdef";
            let mut remote_nonce = "";
            let local_key = self.key.clone();

            let start_negotiation_msg = Message {
                payload: Payload::String(local_nonce.to_string()),
                command: Some(CommandType::SessKeyNegStart),
                seq_nr: Some(1),
                ret_code: None,
            };

            info!(
                "Writing SessKeyNegStart msg to {} ({}):\n{}",
                self.addr, seq_id, &start_negotiation_msg
            );
            tcpstream
                .write_all(self.mp.encode(&start_negotiation_msg, true)?.as_ref())
                .await?;

            let rkey = self.read(&mut tcpstream, seq_id).await?;

            dbg!(&rkey);
        }
        // /v3.4

        info!("Writing message to {} ({}):\n{}", self.addr, seq_id, &mes);
        let bts = tcpstream.write(self.mp.encode(mes, true)?.as_ref()).await?;
        info!("Wrote {} bytes ({})", bts, seq_id);

        self.read(&mut tcpstream, seq_id).await
    }

    async fn read(&self, tcpstream: &mut TcpStream, seq_id: u32) -> Result<Vec<Message>> {
        let mut buf = [0; 256];
        let bts = tcpstream.read(&mut buf).await?;
        info!("Received {} bytes ({})", bts, seq_id);
        if bts == 0 {
            return Err(ErrorKind::BadTcpRead);
        } else {
            debug!(
                "Received response ({}):\n{}",
                seq_id,
                hex::encode(&buf[..bts])
            );
        }
        debug!("Shutting down connection ({})", seq_id);
        tcpstream.shutdown().await?;
        self.mp.parse(&buf[..bts])
    }
}
