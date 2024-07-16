# Swapspace-api rust
[![Crates badge](https://img.shields.io/crates/v/serde_aux.svg)](https://crates.io/crates/swapspace-api)
[![Documentation](https://docs.rs/serde-aux/badge.svg)](https://docs.rs/swapspace-api)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

# Create a new client
```rust
use swapspace_api::SwapSpaceApi;
let api = SwapSpaceApi::new("api_key".to_string()).expect("failed to create client");
```
or set SWAPSPACE_API_KEY env variable and call default
``` rust
use swapspace_api::SwapSpaceApi;
let api = SwapSpaceApi::default();
```

# get currencies
```rust
let api = SwapSpaceApi::default();
api.get_currencies().await.unwrap();
```
# get amounts
``` rust
let api = SwapSpaceApi::default();
let amounts = GetAmounts {
    from_currency: "btc".to_string(),
    from_network: "btc".to_string(),
    to_currency: "eth".to_string(),
    to_network: "eth".to_string(),
    amount: 0.1,
    partner: None,
    fixed: false,
    float: false,
};
let response = api.get_amounts(&amounts).await.unwrap();
```
# get best amount
``` rust
let api = SwapSpaceApi::default();
let amounts = GetAmounts {
    from_currency: "btc".to_string(),
    from_network: "btc".to_string(),
    to_currency: "eth".to_string(),
    to_network: "eth".to_string(),
    amount: 0.1,
    partner: None,
    fixed: false,
    float: false,
};
let response = api.get_amounts_best(&amounts).await.unwrap();
```
# get partners
``` rust
let api = SwapSpaceApi::default();
let response = api.get_partners().await.unwrap();
```
# post exchange
```rust
let api = SwapSpaceApi::default();
let data = ExchangeRequest {
    partner: "simpleswap".to_string(),
    from_currency: "btc".to_string(),
    from_network: "btc".to_string(),
    to_currency: "eth".to_string(),
    to_network: "eth".to_string(),
    address: Address("0x32be343b94f860124dc4fee278fdcbd38c102d88".to_string()),
    amount: 2.0,
    fixed: true,
    extra_id: "".to_string(),
    rate_id: "".to_string(),
    user_ip: "8.8.8.8".to_string(),
    refund: Address("1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX".to_string()),
};
let response = api.post_exchange(data).await.unwrap();
```
# get exchange status
``` rust
let api = SwapSpaceApi::default();
let id = "id";
let response = api.get_exchange_status(id).await.unwrap();
```
