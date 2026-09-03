use hickory_client::proto::rr::{LowerName, Record, RecordType};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::{GenericConnector, TokioConnectionProvider};
use hickory_resolver::{Name, Resolver, TokioResolver};
use hickory_server::authority::Catalog;
use hickory_server::authority::MessageResponse;
use hickory_server::server::ServerFuture;
use hickory_server::store::forwarder::{ForwardAuthority, ForwardConfig};
use nsproxy_common::trace_spawn_result;
use std::io;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::warn;

pub async fn run_dns_ipv4_only() -> anyhow::Result<()> {
    let (config, mut opts) = (ResolverConfig::google(), ResolverOpts::default());
    opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4Only;

    let upstream_resolver =
        Resolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts.clone())
            .build();

    let auth = ForwardAuthority::builder_tokio(ForwardConfig {
        name_servers: NameServerConfigGroup::google(),
        options: Some(opts),
    })
    .build()
    .unwrap();

    let mut catalog = Catalog::new();
    catalog.upsert(LowerName::from(Name::root()), vec![Arc::new(auth)]);

    let wrapper = RequestProxy { internal: catalog };
    let mut server = ServerFuture::new(wrapper);

    let socket = UdpSocket::bind("127.0.0.1:53").await?;
    server.register_socket(socket);

    warn!("Internal DNS running");

    loop {
        trace_spawn_result("dns server", server.block_until_done()).await
    }

    Ok(())
}

pub struct RequestProxy {
    pub internal: Catalog,
}

use hickory_server::server::Request;
use hickory_server::server::RequestHandler;
use hickory_server::server::ResponseHandler;
use hickory_server::server::ResponseInfo;

#[async_trait::async_trait]
impl RequestHandler for RequestProxy {
    /// Determines what needs to happen given the type of request, i.e. Query or Update.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    /// * `response_handle` - sink for the response message to be sent
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &mut Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        request
            .queries
            .queries
            .retain(|query| query.query_type() != RecordType::AAAA);

        self.internal.handle_request(request, response_handle).await
    }
}

#[derive(Clone)]
pub struct ResponseProxy<R: ResponseHandler> {
    pub internal: R,
}

impl<R: ResponseHandler> ResponseHandler for ResponseProxy<R> {
    fn send_response<'a, 'life0, 'life1, 'async_trait>(
        &'life0 mut self,
        response: MessageResponse<
            'life1,
            'a,
            impl 'async_trait + Iterator<Item = &'a Record> + Send + 'a,
            impl 'async_trait + Iterator<Item = &'a Record> + Send + 'a,
            impl 'async_trait + Iterator<Item = &'a Record> + Send + 'a,
            impl 'async_trait + Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = io::Result<ResponseInfo>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'a: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let filtered_response = MessageResponse {
                header: response.header,
                queries: response.queries,
                answers: response
                    .answers
                    .filter(|record| record.record_type() != RecordType::AAAA),
                name_servers: response
                    .name_servers
                    .filter(|record| record.record_type() != RecordType::AAAA),
                soa: response
                    .soa
                    .filter(|record| record.record_type() != RecordType::AAAA),
                additionals: response
                    .additionals
                    .filter(|record| record.record_type() != RecordType::AAAA),
                sig0: response.sig0,
                edns: response.edns,
            };

            self.internal.send_response(filtered_response).await
        })
    }
}
