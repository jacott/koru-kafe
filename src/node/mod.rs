use std::{
    fs, io,
    net::IpAddr,
    sync::{Arc, RwLock, RwLockReadGuard},
};

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::StatusCode;
use session_manager::{Slot, SlotMap};
use tokio::{
    net::UnixListener,
    sync::mpsc::{self},
    task::JoinSet,
};
use upstream_link::{Frame, KoruSocketReader, KoruSocketWriter, Msg};

use crate::{
    Jst, Req, info,
    message::{Decoder, Encoder, GlobalDictDecoder, GlobalDictEncoder, LocalDictEncoder},
    startup::Startup,
};

pub mod client_link;
pub mod client_session;
pub mod model;
pub mod remote_cursors;
pub mod session_manager;
pub mod task;
pub mod upstream_link;

pub use task::Task;

//const VERSION_RELOAD: u8 = 1;
//const VERSION_CLIENT_AHEAD: u8 = 2;
const VERSION_CLIENT_BEHIND: u8 = 3;
const VERSION_GOOD_DICTIONARY: u8 = 4;
const VERSION_BAD_DICTIONARY: u8 = 5;

#[derive(Debug, Clone)]
pub struct ClientSender {
    client_sender: mpsc::Sender<ClientMessage>,
}
impl ClientSender {
    pub fn new(client_sender: mpsc::Sender<ClientMessage>) -> Self {
        Self { client_sender }
    }

    pub async fn send(
        &self,
        msg: ClientMessage,
    ) -> Result<(), mpsc::error::SendError<ClientMessage>> {
        self.client_sender.send(msg).await
    }
}

pub const CLIENT_QUEUE_CAPICITY: usize = 16;

pub type ClientRegistry = SlotMap<ClientSender>;

#[derive(Default)]
struct NodeJsComms {
    upstream_tx: Option<mpsc::Sender<Frame>>,
    version: Bytes,
    version_hash: Bytes,
    full_msg: Bytes,
    short_msg: Bytes,
    dict_msg: Bytes,
    global_dict_decoder: Arc<GlobalDictDecoder>,
    global_dict_encoder: Arc<GlobalDictEncoder>,
    clients: ClientRegistry,
}
impl NodeJsComms {
    fn init_message(&self, byte: u8) -> Bytes {
        match byte {
            VERSION_BAD_DICTIONARY => self.dict_msg.clone(),
            VERSION_GOOD_DICTIONARY => self.short_msg.clone(),
            VERSION_CLIENT_BEHIND => self.full_msg.clone(),
            _ => Bytes::new(),
        }
    }
}
struct TsNodeInner {
    nodejs_uds: String,
    njs_comms: RwLock<NodeJsComms>,
}
impl TsNodeInner {
    #[inline(always)]
    fn njs_comms(&self) -> RwLockReadGuard<'_, NodeJsComms> {
        self.njs_comms.read().expect("poisoned")
    }
}

#[derive(Clone)]
pub struct ClientConnect {
    pub task: Task,
    pub init_message: Bytes,
    pub upstream_tx: mpsc::Sender<Frame>,
    pub slot: Slot,
    pub version_match: u8,
}
impl ClientConnect {
    fn is_reload(&self) -> bool {
        !matches!(
            self.version_match,
            VERSION_BAD_DICTIONARY | VERSION_GOOD_DICTIONARY | VERSION_CLIENT_BEHIND
        )
    }
}
impl std::fmt::Debug for ClientConnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthClient")
            .field("slot", &self.slot)
            .finish()
    }
}

#[derive(Debug)]
pub enum ClientMessage {
    AuthResponse(Box<ClientConnect>),
    Msg(Msg),
    Err(StatusCode),
}

pub struct ClientConnectMessage(Bytes, mpsc::Sender<ClientMessage>);
impl ClientConnectMessage {
    pub fn new(req: &Req, ip_addr: &IpAddr) -> (Self, mpsc::Receiver<ClientMessage>) {
        let mut data = BytesMut::new();
        if let Some(uri) = req.uri().path_and_query() {
            data.extend_from_slice(uri.as_str().as_bytes());
        } else {
            data.put_u8(b'/');
        }
        data.put_u8(0);

        data.extend_from_slice(ip_addr.to_string().as_bytes());
        data.put_u8(0);

        for (name, value) in req.headers() {
            data.extend_from_slice(name.as_str().as_bytes());
            data.put_u8(0xff);
            data.extend_from_slice(value.as_bytes());
            data.put_u8(0);
        }
        let (tx, rx) = mpsc::channel(32);
        (Self(data.into(), tx), rx)
    }

    pub fn split(self) -> (Bytes, mpsc::Sender<ClientMessage>) {
        (self.0, self.1)
    }

    pub fn bytes(&self) -> Bytes {
        self.0.clone()
    }
}

#[derive(Clone)]
pub struct KoruNode {
    inner: Arc<TsNodeInner>,
}
impl KoruNode {
    pub fn new(nodejs_uds: String) -> Self {
        Self {
            inner: Arc::new(TsNodeInner {
                nodejs_uds,
                njs_comms: RwLock::new(Default::default()),
            }),
        }
    }

    pub fn start_client_connect() -> mpsc::Sender<ClientConnectMessage> {
        let (tx, mut rx) = mpsc::channel::<ClientConnectMessage>(CLIENT_QUEUE_CAPICITY);
        tokio::spawn(Task::scope(async move {
            while let Some(msg) = rx.recv().await {
                Task::global().node().connect_client(msg).await;
            }
        }));
        tx
    }

    pub fn global_dict_encoder(&self) -> Arc<GlobalDictEncoder> {
        self.inner.njs_comms().global_dict_encoder.clone()
    }

    pub fn global_dict_decoder(&self) -> Arc<GlobalDictDecoder> {
        self.inner.njs_comms().global_dict_decoder.clone()
    }

    fn add_client(
        &self,
        client_tx: mpsc::Sender<ClientMessage>,
    ) -> Option<(mpsc::Sender<Frame>, Slot)> {
        let mut guard = self.inner.njs_comms.write().expect("poisoned");
        let tx = guard.upstream_tx.clone()?;
        let client_conn = ClientSender::new(client_tx);
        let slot = guard.clients.insert(client_conn)?;
        Some((tx, slot))
    }

    pub async fn connect_client(&self, msg: ClientConnectMessage) -> Option<Slot> {
        let (msg, client_tx) = msg.split();
        match self.add_client(client_tx.clone()) {
            Some((tx, slot)) => {
                if tx.send(Frame::connect(slot, msg)).await.is_err() {
                    let _ = client_tx
                        .send(ClientMessage::Err(StatusCode::SERVICE_UNAVAILABLE))
                        .await;
                }
                Some(slot)
            }

            None => {
                let _ = client_tx
                    .send(ClientMessage::Err(StatusCode::SERVICE_UNAVAILABLE))
                    .await;
                None
            }
        }
    }

    pub(crate) fn set_init_msg(
        &self,
        mut msg: Bytes,
        upstream_tx: mpsc::Sender<Frame>,
    ) -> Option<()> {
        let full_msg = msg.slice(..);
        // b'X'
        msg.get_u8();
        let gdd = GlobalDictDecoder::default();
        let mut dec = Decoder::new(msg, &gdd);

        let version = dec.get_string_as_bytes()?;
        let version_hash = dec.get_string_as_bytes()?;

        if let Some(Jst::Uint8Array(dict)) = dec.next() {
            let global_dict_decoder = Arc::new(GlobalDictDecoder::new(&dict));
            let global_dict_encoder = Arc::new(
                match GlobalDictEncoder::from_decoder(&global_dict_decoder) {
                    Ok(v) => v,
                    Err(err) => panic!("{err:?}"),
                },
            );

            let dict_hash = dec.get_string_as_bytes()?;
            let fields = [
                Jst::string(""),
                Jst::string(version_hash.clone()),
                Jst::Uint8Array(dict),
                Jst::string(dict_hash),
            ];
            let short_msg = encode_dict_msg(&fields[..2]);
            let dict_msg = encode_dict_msg(&fields);

            let mut guard = self.inner.njs_comms.write().expect("poisoned");
            guard.upstream_tx = Some(upstream_tx);
            guard.version = version;
            guard.version_hash = version_hash;
            guard.full_msg = full_msg;
            guard.short_msg = short_msg;
            guard.dict_msg = dict_msg;
            guard.global_dict_decoder = global_dict_decoder;
            guard.global_dict_encoder = global_dict_encoder;

            Some(())
        } else {
            None
        }
    }

    fn get_client(&self, slot: Slot) -> Option<ClientSender> {
        let guard = self.inner.njs_comms.read().expect("poisoned");
        guard.clients.get(slot).cloned()
    }
    fn drop_client(&self, slot: Slot) {
        self.inner
            .njs_comms
            .write()
            .expect("poisoned")
            .clients
            .remove(slot);
    }

    fn auth_response(&self, slot: Slot, bytes: &Bytes) -> Option<(ClientSender, ClientMessage)> {
        let guard = self.inner.njs_comms.read().expect("poisoned");
        let upstream_tx = guard.upstream_tx.as_ref()?.clone();

        let version_match = if bytes.len() == 1 { bytes[0] } else { 0 };

        Some((
            guard.clients.get(slot)?.clone(),
            ClientMessage::AuthResponse(Box::new(ClientConnect {
                task: Task::local(),
                init_message: guard.init_message(version_match),
                upstream_tx,
                slot,
                version_match,
            })),
        ))
    }
}
#[async_trait]
impl Startup for KoruNode {
    async fn start(&self) {
        let mut jset = JoinSet::new();
        jset.spawn(Task::scope(start_uds(
            self.clone(),
            self.inner.nodejs_uds.clone(),
        )));
        jset.join_next().await;
        jset.shutdown().await;
    }
}
impl crate::domain::Conf for KoruNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "TsAccount"
    }
}

async fn start_uds(koru_node: KoruNode, path: String) {
    match fs::remove_file(&path) {
        Ok(_) => (),
        Err(error) => match error.kind() {
            io::ErrorKind::NotFound => (),
            other_error => {
                panic!("Problem removing socket {:?}", other_error)
            }
        },
    }

    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) => {
            panic!("Can't bind listener to \"{}\": {:?}", &path, error.kind())
        }
    };

    loop {
        info!("{} wait for server...", &path);
        let socket = listener.accept().await.expect("listener.accept failure").0;
        info!("connected");
        let (srx, stx) = socket.into_split();
        let mut kreader = KoruSocketReader::new(srx);
        let mut kwriter = KoruSocketWriter::new(stx);

        let (upstream_tx, mut upstream_rx) = mpsc::channel(1);

        // init connection
        {
            let frame = Frame::request_dictionary();
            if kwriter.write_msg(&frame).await.is_err() {
                continue;
            }
        }

        match kreader.read_msg().await {
            Ok(Some(Frame {
                msg: upstream_link::Msg::Binary(bytes),
                slot,
            })) if slot.is_control() && matches!(bytes.first(), Some(b'X')) => {
                koru_node.set_init_msg(bytes, upstream_tx.clone());
            }
            Ok(Some(_)) => info!("Unexpected msg"),
            Ok(None) => {}
            Err(err) => info!("UDS read error {:?}", err),
        }

        let mut js = JoinSet::new();

        // write message to nodejs
        let kn2 = koru_node.clone();
        js.spawn(async move {
            while let Some(frame) = upstream_rx.recv().await {
                if matches!(frame.msg, Msg::Close) {
                    kn2.drop_client(frame.slot);
                }
                if kwriter.write_msg(&frame).await.is_err() {
                    break;
                }
            }
        });

        // read message from nodejs
        let kn3 = koru_node.clone();
        js.spawn(Task::scope(async move {
            while let Ok(Some(Frame { msg, slot })) = kreader.read_msg().await {
                match msg {
                    Msg::Connect(bytes) => {
                        if let Some((client, authc)) = kn3.auth_response(slot, &bytes)
                            && client.send(authc).await.is_ok()
                        {
                            continue;
                        }
                    }
                    Msg::Binary(_) | Msg::Text(_) => {
                        if let Some(client) = kn3.get_client(slot)
                            && client.send(ClientMessage::Msg(msg)).await.is_ok()
                        {
                            continue;
                        }
                    }
                    Msg::Close => {}
                }

                kn3.drop_client(slot);
            }
        }));

        js.join_next().await;

        js.shutdown().await;
    }
}

fn encode_dict_msg(fields: &[Jst]) -> Bytes {
    let gde = GlobalDictEncoder::default();
    let lde = LocalDictEncoder::new(&gde);
    let mut enc = Encoder::new(b'X', lde);
    for o in fields {
        enc.add(o);
    }
    if fields.len() == 2 {
        enc.add(&Jst::Null);
        enc.add(&Jst::Undefined);
    }
    let mut msg = enc.encode();
    msg.copy_to_bytes(msg.remaining())
}

#[cfg(test)]
pub mod test_helper {
    use crate::{id::Id, websockets::Message};
    use tokio::sync::mpsc;

    use super::{client_session::ClientSession, session_manager::Slot};

    pub fn client_session<I: Into<Id>>(
        slot: u16,
        user_id: I,
        db_id: I,
    ) -> (ClientSession, mpsc::Receiver<Message>) {
        let slot: Slot = slot.into();
        let (upstream_tx, _upstream_rx) = mpsc::channel(10);
        let (client_sink, client_rx) = mpsc::channel::<Message>(32);
        let client_sess = ClientSession::new(slot, client_sink, upstream_tx);
        client_sess.set_user_and_db_id(user_id.into(), db_id.into());
        (client_sess, client_rx)
    }
}

#[cfg(test)]
#[path = "mod_test.rs"]
mod test;
