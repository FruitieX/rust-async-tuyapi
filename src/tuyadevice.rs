//! # TuyaDevice
//! The TuyaDevice represents a communication channel with a Tuya compatible device. It
//! encapsulates the device key, version and ip address. By supplying a Payload to either set() or
//! get() functions the framework takes care of sending and receiving the reply from the device.
//!
//! The TuyaDevice is the high level device communication API. To get in to the nitty gritty
//! details, create a MessageParser.
use crate::error::ErrorKind;
use crate::mesparse::{CommandType, Message, MessageParser, TuyaVersion};
use crate::{ControlNewPayload, ControlNewPayloadData, Payload, PayloadStruct, Result};
use log::{debug, info};
use openssl::symm::{Cipher, Crypter};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

#[derive(Default)]
pub struct SeqId {
    seq_id: u32,
}

impl SeqId {
    pub fn current(&self) -> u32 {
        self.seq_id
    }

    pub fn next_id(&mut self) -> u32 {
        self.seq_id += 1;
        self.seq_id
    }
}

pub struct TuyaConnection {
    seq_id: SeqId,
    tcp_stream: TcpStream,
    mp: MessageParser,
}

impl TuyaConnection {
    async fn send(&mut self, mes: &Message) -> Result<Vec<Message>> {
        info!(
            "Writing message to {} ({}):\n",
            self.tcp_stream.peer_addr()?,
            &mes
        );
        let mut mes = (*mes).clone();
        if matches!(mes.seq_nr, None) {
            mes.seq_nr = Some(self.seq_id.next_id());
        }
        self.tcp_stream
            .write_all(self.mp.encode(&mes, true)?.as_ref())
            .await?;
        // info!("Wrote {} bytes", bts);

        self.read().await
    }

    async fn read(&mut self) -> Result<Vec<Message>> {
        let mut buf = [0; 1024];
        let mut bts = 0;
        let mut attempts = 0;

        while bts == 0 && attempts < 3 {
            bts = self.tcp_stream.read(&mut buf).await?;
            info!("Received {} bytes", bts);
            attempts += 1;
            sleep(Duration::from_millis(100)).await;
        }

        if bts == 0 {
            return Err(ErrorKind::BadTcpRead);
        } else {
            debug!("Received response:\n{}", hex::encode(&buf[..bts]));
        }
        self.mp.parse(&buf[..bts])
    }
}

pub struct TuyaDevice {
    addr: SocketAddr,
    device_id: String,
    key: Option<String>,
    version: TuyaVersion,
    connection: Option<TuyaConnection>,
}

impl TuyaDevice {
    pub fn new(ver: &str, device_id: &str, key: Option<&str>, addr: IpAddr) -> Result<TuyaDevice> {
        let version = ver.parse()?;
        Ok(TuyaDevice {
            device_id: device_id.to_string(),
            addr: SocketAddr::new(addr, 6668),
            key: key.map(|k| k.to_string()),
            version,
            connection: Default::default(),
        })
    }

    pub async fn connect(&mut self) -> Result<()> {
        let tcp_stream = TcpStream::connect(&self.addr).await?;
        tcp_stream.set_nodelay(true)?;

        let mp = MessageParser::create(self.version.clone(), self.key.clone())?;
        let connection = TuyaConnection {
            mp,
            seq_id: Default::default(),
            tcp_stream,
        };

        self.connection = Some(connection);

        // Tuya protocol v3.4 requires session key negotiation
        if self.version == TuyaVersion::ThreeFour {
            let connection = self.connection.as_mut().unwrap();

            let local_nonce = b"0123456789abcdef";
            let local_key = self.key.clone().ok_or(ErrorKind::MissingKey)?;

            let start_negotiation_msg = Message {
                payload: Payload::Raw(local_nonce.to_vec()),
                command: Some(CommandType::SessKeyNegStart),
                seq_nr: Some(connection.seq_id.next_id()),
                ret_code: None,
            };

            info!(
                "Writing SessKeyNegStart msg to {} ({}):\n{}",
                self.addr,
                connection.seq_id.current(),
                &start_negotiation_msg
            );
            connection
                .tcp_stream
                .write_all(connection.mp.encode(&start_negotiation_msg, true)?.as_ref())
                .await?;

            let rkey = connection.read().await?;
            let rkey = rkey.into_iter().next().ok_or(ErrorKind::MissingRemoteKey)?;
            let rkey = match rkey.payload {
                Payload::Raw(s) if s.len() == 48 => Ok(s),
                _ => Err(ErrorKind::InvalidRemoteKey),
            }?;

            let remote_nonce = &rkey[..16];
            // let remote_nonce = b"1123456789abcdef";
            let _hmac = &rkey[16..48];

            let rkey_hmac = connection.mp.cipher.hmac(remote_nonce)?;

            let session_negotiation_finish_msg = Message {
                payload: Payload::Raw(rkey_hmac),
                command: Some(CommandType::SessKeyNegFinish),
                seq_nr: Some(connection.seq_id.next_id()),
                ret_code: None,
            };

            info!(
                "Writing SessKeyNegFinish msg to {} ({}):\n{}",
                self.addr,
                connection.seq_id.current(),
                &session_negotiation_finish_msg
            );
            connection
                .tcp_stream
                .write_all(
                    connection
                        .mp
                        .encode(&session_negotiation_finish_msg, true)?
                        .as_ref(),
                )
                .await?;

            let nonce_xor: Vec<u8> = local_nonce
                .iter()
                .zip(remote_nonce.iter())
                .map(|(&a, &b)| a ^ b)
                .collect();

            debug!("nonce_xor: {}", hex::encode(&nonce_xor));

            debug!("using local_key for crypter: {}", hex::encode(&local_key));
            let mut session_key = vec![0u8; nonce_xor.len() + Cipher::aes_128_ecb().block_size()];
            let mut c = Crypter::new(
                Cipher::aes_128_ecb(),
                openssl::symm::Mode::Encrypt,
                local_key.as_bytes(),
                None,
            )
            .unwrap();

            c.pad(false);
            let mut count = c.update(nonce_xor.as_slice(), &mut session_key)?;
            count += c.finalize(&mut session_key[count..])?;
            session_key.truncate(count);

            debug!("session key: {}", hex::encode(&session_key));

            connection.mp.cipher.set_key(session_key);
        }

        Ok(())
    }

    pub async fn set(&mut self, tuya_payload: Payload) -> Result<()> {
        let connection = self.connection.as_mut().ok_or(ErrorKind::NotConnected)?;
        let command = match self.version {
            TuyaVersion::ThreeOne | TuyaVersion::ThreeThree => CommandType::Control,
            TuyaVersion::ThreeFour => CommandType::ControlNew,
        };
        let mes = Message::new(tuya_payload, command);
        let replies = connection.send(&mes).await?;
        replies
            .iter()
            .for_each(|mes| info!("Decoded response:\n{}", mes));
        Ok(())
    }

    pub async fn set_value(&mut self, index: u32, value: serde_json::Value) -> Result<()> {
        let mut dps = HashMap::new();
        dps.insert(index.to_string(), value);

        self.set_values(dps).await
    }

    pub async fn set_values(&mut self, dps: HashMap<String, serde_json::Value>) -> Result<()> {
        let connection = self.connection.as_mut().ok_or(ErrorKind::NotConnected)?;
        let command = match self.version {
            TuyaVersion::ThreeOne | TuyaVersion::ThreeThree => CommandType::Control,
            TuyaVersion::ThreeFour => CommandType::ControlNew,
        };

        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        // let current_time = 1;

        let device_id = self.device_id.clone();

        let payload = match self.version {
            TuyaVersion::ThreeOne | TuyaVersion::ThreeThree => Payload::Struct(PayloadStruct {
                gw_id: Some(device_id.clone()),
                dev_id: device_id.clone(),
                uid: Some(device_id.clone()),
                t: Some(current_time.to_string()),
                dp_id: None,
                dps: Some(dps),
            }),
            TuyaVersion::ThreeFour => Payload::ControlNewStruct(ControlNewPayload {
                protocol: 5,
                t: current_time,
                data: ControlNewPayloadData { dps },
            }),
        };
        let mes = Message::new(payload, command);
        let replies = connection.send(&mes).await?;
        replies
            .iter()
            .for_each(|mes| info!("Decoded response:\n{}", mes));
        Ok(())
    }

    pub async fn get(&mut self, tuya_payload: Payload) -> Result<Vec<Message>> {
        let connection = self.connection.as_mut().ok_or(ErrorKind::NotConnected)?;
        let command = match self.version {
            TuyaVersion::ThreeOne | TuyaVersion::ThreeThree => CommandType::DpQuery,
            TuyaVersion::ThreeFour => CommandType::DpQueryNew,
        };
        let mes = Message::new(tuya_payload, command);
        let replies = connection.send(&mes).await?;
        replies
            .iter()
            .for_each(|mes| info!("Decoded response:\n{}", mes));
        Ok(replies)
    }

    pub async fn refresh(&mut self, tuya_payload: Payload) -> Result<Vec<Message>> {
        let connection = self.connection.as_mut().ok_or(ErrorKind::NotConnected)?;
        let mes = Message::new(tuya_payload, CommandType::DpRefresh);
        let replies = connection.send(&mes).await?;
        replies
            .iter()
            .for_each(|mes| info!("Decoded response:\n{}", mes));
        Ok(replies)
    }
}
