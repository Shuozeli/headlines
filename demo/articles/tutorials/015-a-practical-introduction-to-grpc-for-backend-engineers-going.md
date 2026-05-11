---
title: "A Practical Introduction to gRPC for Backend Engineers: Going Deeper"
author_name: "Priya Shah"
author_url: "https://example.com"
created_at: "2026-04-21T15:08:00Z"
state: "live"
---

**A note up front:** this piece extends an earlier post on the same topic with new examples.


gRPC has earned a reputation for being heavyweight, but most of that
reputation is undeserved. Once you've written a `.proto` file and let
`tonic` or `grpc-go` handle the codegen, the day-to-day developer
experience is excellent.

You need a recent Rust toolchain (1.75 or newer), `protoc`, and
familiarity with async Rust. If you're new to async, the gRPC-specific
parts of this tutorial are still followable; the rest will read like a
crash course.

## Prerequisites

This tutorial walks through building a small `EchoService` from scratch.
We'll cover schema definition, code generation, server implementation,
and a client. By the end you'll have a working binary you can extend
into something real.

## Step 1: Define the schema

Create `proto/echo/v1/echo.proto`:

```proto
syntax = "proto3";
package echo.v1;

service EchoService {
    rpc Echo(EchoRequest) returns (EchoReply);
}

message EchoRequest { string message = 1; }
message EchoReply { string message = 1; }
```

That's our entire wire surface. One method, one request type, one reply.

## Step 2: Generate Rust code

`tonic-build` runs at compile time. In `build.rs`:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/echo/v1/echo.proto")?;
    Ok(())
}
```

Add to `Cargo.toml`:

```toml
[dependencies]
tonic = "0.12"
prost = "0.13"
tokio = { version = "1", features = ["full"] }

[build-dependencies]
tonic-build = "0.12"
```

Now `cargo build` produces the trait, request, reply, and server/client
stubs.

## Step 3: Implement the service

```rust
use tonic::{Request, Response, Status};

pub mod echo {
    tonic::include_proto!("echo.v1");
}

use echo::echo_service_server::{EchoService, EchoServiceServer};
use echo::{EchoReply, EchoRequest};

#[derive(Default)]
pub struct MyEcho;

#[tonic::async_trait]
impl EchoService for MyEcho {
    async fn echo(
        &self,
        req: Request<EchoRequest>,
    ) -> Result<Response<EchoReply>, Status> {
        let msg = req.into_inner().message;
        Ok(Response::new(EchoReply { message: msg }))
    }
}
```

## Step 4: Wire up the server

```rust
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:50051".parse()?;
    let svc = MyEcho;
    Server::builder()
        .add_service(EchoServiceServer::new(svc))
        .serve(addr)
        .await?;
    Ok(())
}
```

`cargo run` and you have a working gRPC server. Test it with `grpcurl`.

## Step 5: Build a client

The same crate produces client stubs. Pull `EchoServiceClient` from the
generated module, build a `tonic::transport::Channel`, and call
`.echo(...)`. The interface is plain async Rust — no special idioms.

## Where to go next

Real services need authentication, observability, error handling,
streaming, and graceful shutdown. Each is a separate concern and each
has well-trodden patterns in the tonic ecosystem. We'll cover the
auth piece in the next tutorial.

Until then: write a `.proto`, let codegen do the work, and treat gRPC
like any other library.
