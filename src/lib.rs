use chrono::{DateTime, NaiveDateTime, Utc};
use envconfig::Envconfig;
use regex::Regex;
use reqwest::{
    header::{HeaderMap, HeaderValue, InvalidHeaderName, InvalidHeaderValue},
    Client, Method, StatusCode, Url,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

const BASE_URL: &str = "https://api.swapspace.co/api/v2/";

/// all possible errors from the API and their corresponding error messages
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error(transparent)]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error(transparent)]
    InvalidHeaderName(#[from] InvalidHeaderName),
    #[error(transparent)]
    UrlError(#[from] url::ParseError),
    /// 401 Access denied. Invalid api key.
    #[error("Access denied. Invalid api key.")]
    InvalidApiKey,
    /// 401 Access denied. No api key provided.
    #[error("Access denied. No api key provided.")]
    NoApiKey,
    /// 429 Too many requests, your key access is suspended until 2023-01-01 00:00 UTC.
    #[error("Too many requests, your key access is suspended until {0}")]
    TooManyRequests(DateTime<Utc>),
    /// 500 Internal Server Error
    #[error("Internal Server Error")]
    InternalServerError,
    /// 422 Partner not found
    #[error("Partner not found")]
    PartnerNotFound,
    /// 422 Currencies not found: 123-btc
    #[error("Currencies not found: {0}")]
    CurrenciesNotFound(String),
    /// 422 Invalid param "amount"
    #[error("Invalid param {0}")]
    InvalidParam(String),
    /// 422 No partners found using filter: 123
    #[error("No partners found using filter: #{0}")]
    NoPartnersFoundUsingFilter(String),
    /// 400 Missing required param "fromCurrency"
    #[error("Missing required param {0}")]
    MissingParam(String),
    /// 400 The following required params are missing: partner
    #[error("The following required params are missing: {0}")]
    MissingRequiredParams(String),
    /// 422 Currency not found: btc123-btc
    #[error("Currency not found: {0}")]
    CurrencyNotFound(String),
    /// 400 Partner FixedFloat does not support fixed type of exchanges
    #[error("Partner {0} does not support fixed type of exchanges")]
    PartnerDoesNotSupportFixed(String),
    /// 422 Pair cannot be processed by fixedfloat
    #[error("Pair cannot be processed by {0}")]
    PartnerCannotProcessPair(String),
    /// 422 Validation of address failed
    #[error("Validation of address failed")]
    ValidationOfAddressFailed,
    /// 422 The following refund address invalid
    #[error("The following refund address invalid")]
    RefundAddressInvalid,
    /// 422 userIp is incorrect
    #[error("userIp is incorrect")]
    UserIpIsIncorrect,
    /// 422 Amount request failed
    #[error("Amount request failed")]
    AmountRequestFailed,
    /// 403 IP address is forbidden
    #[error("IP address is forbidden")]
    IpAddressIsForbidden,
    /// 422 Amount minimum is 0.00019451
    #[error("Amount minimum is {0}")]
    AmountMinimum(f64),
    /// 422 Amount maximum is 1.8146447
    #[error("Amount maximum is {0}")]
    AmountMaximum(f64),
    /// 404 Exchange not found
    #[error("Exchange not found")]
    ExchangeNotFound,
    #[error("Unmatched error: {0}")]
    UnmatchedError(String),
}

impl From<(StatusCode, String)> for Error {
    fn from(val: (StatusCode, String)) -> Self {
        match val {
            (StatusCode::UNAUTHORIZED, text) => match text.as_str() {
                "Access denied. Invalid api key." => Error::InvalidApiKey,
                "Access denied. No api key provided." => Error::NoApiKey,
                _ => Error::UnmatchedError(text),
            },
            (StatusCode::TOO_MANY_REQUESTS, text) => text
                .strip_prefix("Too many requests, your key access is suspended until ")
                .map_or_else(
                    || Error::UnmatchedError(text.clone()),
                    |date| {
                        NaiveDateTime::parse_from_str(date, "%Y-%m-%d %H:%M UTC.")
                            .as_ref()
                            .map(NaiveDateTime::and_utc)
                            .map_or_else(
                                |_| Error::UnmatchedError(text.clone()),
                                Error::TooManyRequests,
                            )
                    },
                ),
            (StatusCode::BAD_REQUEST, text) => match text.as_str() {
                t if t.starts_with("Missing required param ") => t
                    .strip_prefix("Missing required param ")
                    .map(|param| Error::MissingParam(param.to_string()))
                    .unwrap(),
                t if t.starts_with("The following required params are missing: ") => t
                    .strip_prefix("The following required params are missing: ")
                    .map(|params| Error::MissingRequiredParams(params.to_string()))
                    .unwrap(),
                t if t.starts_with("Partner ")
                    && t.ends_with(" does not support fixed type of exchanges") =>
                {
                    t.strip_prefix("Partner ")
                        .unwrap()
                        .strip_suffix(" does not support fixed type of exchanges")
                        .map(|partner| Error::PartnerDoesNotSupportFixed(partner.to_string()))
                        .unwrap()
                }
                _ => Error::UnmatchedError(text),
            },
            (StatusCode::INTERNAL_SERVER_ERROR, _) => Error::InternalServerError,
            (StatusCode::UNPROCESSABLE_ENTITY, text) => match text.as_str() {
                "Partner not found" => Error::PartnerNotFound,
                "Validation of address failed" => Error::ValidationOfAddressFailed,
                "The following refund address invalid" => Error::RefundAddressInvalid,
                "userIp is incorrect" => Error::UserIpIsIncorrect,
                "Amount request failed" => Error::AmountRequestFailed,
                t if t.starts_with("No partners found using filter: ") => t
                    .strip_prefix("No partners found using filter: ")
                    .map(|filter| Error::NoPartnersFoundUsingFilter(filter.to_string()))
                    .unwrap(),
                t if t.starts_with("Currencies not found: ") => t
                    .strip_prefix("Currencies not found: ")
                    .map(|currency| Error::CurrenciesNotFound(currency.to_string()))
                    .unwrap(),
                t if t.starts_with("Invalid param ") => t
                    .strip_prefix("Invalid param ")
                    .map(|param| Error::InvalidParam(param.to_string()))
                    .unwrap(),
                t if t.starts_with("Missing required param ") => t
                    .strip_prefix("Missing required param ")
                    .map(|param| Error::MissingParam(param.to_string()))
                    .unwrap(),
                t if t.starts_with("Currency not found: ") => t
                    .strip_prefix("Currency not found: ")
                    .map(|currency| Error::CurrencyNotFound(currency.to_string()))
                    .unwrap(),
                t if t.starts_with("Pair cannot be processed by ") => t
                    .strip_prefix("Pair cannot be processed by ")
                    .map(|partner| Error::PartnerCannotProcessPair(partner.to_string()))
                    .unwrap(),
                t if t.starts_with("Amount minimum is ") => t
                    .strip_prefix("Amount minimum is ")
                    .map(|amount| {
                        amount.parse().map_or_else(
                            |_| Error::UnmatchedError(text.clone()),
                            Error::AmountMinimum,
                        )
                    })
                    .unwrap(),
                t if t.starts_with("Amount maximum is ") => t
                    .strip_prefix("Amount maximum is ")
                    .map(|amount| {
                        amount.parse().map_or_else(
                            |_| Error::UnmatchedError(text.clone()),
                            Error::AmountMaximum,
                        )
                    })
                    .unwrap(),
                _ => Error::UnmatchedError(text),
            },
            (StatusCode::FORBIDDEN, _) => Error::IpAddressIsForbidden,
            (StatusCode::NOT_FOUND, _) => Error::ExchangeNotFound,
            (_, text) => Error::UnmatchedError(text),
        }
    }
}

#[derive(Envconfig)]
pub struct Config {
    #[envconfig(from = "SWAPSPACE_API_KEY")]
    pub swapspace_api_key: String,
}

impl Default for SwapSpaceApi {
    fn default() -> Self {
        let config = Config::init_from_env().expect("Failed to read environment variables");
        Self::new(config.swapspace_api_key.clone()).expect("Failed to create reqwest client")
    }
}

pub struct SwapSpaceApi {
    pub client: Client,
    pub base_url: Url,
}

#[derive(Debug, Clone)]
pub struct GetAmounts {
    pub from_currency: String,
    pub from_network: String,
    pub to_currency: String,
    pub to_network: String,
    pub amount: f64,
    pub partner: Option<Vec<String>>,
    pub fixed: bool,
    pub float: bool,
}

#[derive(Debug, Clone)]
pub struct ValidationRegexp(pub Regex);

impl ValidationRegexp {
    pub fn new(validation_regexp: &str) -> Result<Self, regex::Error> {
        let regexp = validation_regexp
            .strip_prefix('/')
            .unwrap_or(validation_regexp)
            .strip_suffix('/')
            .unwrap_or(validation_regexp);
        Regex::new(regexp).map(Self)
    }
}

fn deserialize_validation_regexp<'de, D>(deserializer: D) -> Result<ValidationRegexp, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let validation_regexp = String::deserialize(deserializer)?;
    ValidationRegexp::new(&validation_regexp).map_err(serde::de::Error::custom)
}

#[derive(Default, Clone, Serialize, Deserialize, Debug)]
pub struct Address(pub String);

impl Address {
    pub fn new(address: String, validation_regexp: &ValidationRegexp) -> Result<Self, Error> {
        if !validation_regexp.0.is_match(&address) {
            Err(Error::ValidationOfAddressFailed)
        } else {
            Ok(Self(address))
        }
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeRequest {
    pub partner: String,
    pub from_currency: String,
    pub from_network: String,
    pub to_currency: String,
    pub to_network: String,
    pub address: Address,
    pub amount: f64,
    pub fixed: bool,
    pub extra_id: String,
    pub rate_id: String,
    pub user_ip: String,
    pub refund: Address,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CurrencyResponse {
    pub name: String,
    pub extra_id_name: String,
    pub icon: String,
    pub deposit: bool,
    pub withdrawal: bool,
    #[serde(deserialize_with = "deserialize_validation_regexp")]
    pub validation_regexp: ValidationRegexp,
    pub contract_address: Option<String>,
    pub code: String,
    pub network: String,
    pub has_extra_id: bool,
    pub id: String,
    pub popular: bool,
    pub fiat: Option<bool>,
    pub buy: Option<bool>,
    pub network_name: Option<String>,
}
pub type Currencies = Vec<CurrencyResponse>;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PartnerResponse {
    pub fixed: bool,
    pub float: bool,
    pub req_fixed_refund: bool,
    pub req_float_refund: bool,
    pub name: String,
    pub path: String,
    pub fiat_provider: Option<bool>,
    pub prohibited_countries: Option<Vec<String>>,
    pub kyc_level: Option<String>,
}
pub type Partners = Vec<PartnerResponse>;

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AmountResponse {
    pub partner: String,
    pub from_amount: f64,
    pub to_amount: f64,
    pub from_currency: String,
    pub from_network: String,
    pub to_currency: String,
    pub to_network: String,
    pub support_rate: u32,
    pub duration: String,
    pub fixed: bool,
    pub min: f64,
    pub max: f64,
    pub exists: bool,
    pub id: String,
}
pub type Amounts = Vec<AmountResponse>;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Timestamps {
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeCurrency {
    pub code: String,
    pub network: String,
    pub amount: f64,
    pub address: String,
    pub extra_id: String,
    pub transaction_hash: String,
    pub contract_address: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BlockExplorerUrl {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeResponse {
    pub id: String,
    pub partner: String,
    pub fixed: bool,
    pub timestamps: Timestamps,
    pub from: ExchangeCurrency,
    pub to: ExchangeCurrency,
    pub rate: f64,
    pub status: String,
    pub confirmations: i32,
    pub refund_extra_id: String,
    pub block_explorer_transaction_url: BlockExplorerUrl,
    pub block_explorer_address_url: BlockExplorerUrl,
    pub payment_url: Option<String>,
    pub refund_address: Option<String>,
    pub error: Option<bool>,
    pub token: Option<String>,
    pub warnings: BlockExplorerUrl,
}

impl From<AmountResponse> for GetAmounts {
    fn from(amount: AmountResponse) -> Self {
        Self {
            from_currency: amount.from_currency,
            from_network: amount.from_network,
            to_currency: amount.to_currency,
            to_network: amount.to_network,
            amount: amount.from_amount,
            partner: None,
            fixed: false,
            float: false,
        }
    }
}

impl SwapSpaceApi {
    /// create a new instance of the SwapSpaceApi client using new
    /// or use the default method to create a new instance
    /// it would read the api key from the environment variable SWAPSPACE_API_KEY
    /// ```
    /// use swapspace_api::SwapSpaceApi;
    /// let api = SwapSpaceApi::new("api_key".to_string());
    /// assert_eq!(api.is_ok(), true);
    /// let api = SwapSpaceApi::default();
    /// ```
    pub fn new(api_key: String) -> Result<Self, Error> {
        if api_key.is_empty() {
            return Err(Error::NoApiKey);
        }
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", HeaderValue::from_str(&api_key)?);
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));
        let client = Client::builder().default_headers(headers).build()?;
        let base_url = BASE_URL.parse().unwrap();
        Ok(Self { client, base_url })
    }

    fn get_full_url(&self, endpoint: &str, params: Option<&GetAmounts>) -> Result<Url, Error> {
        let mut url = self.base_url.join(endpoint)?;
        let mut url_builder = url.query_pairs_mut();
        if let Some(params) = params {
            url_builder.append_pair("fromCurrency", &params.from_currency);
            url_builder.append_pair("fromNetwork", &params.from_network);
            url_builder.append_pair("toCurrency", &params.to_currency);
            url_builder.append_pair("toNetwork", &params.to_network);
            url_builder.append_pair("amount", &params.amount.to_string());
            if let Some(partner) = &params.partner {
                url_builder.append_pair("partner", &partner.join(","));
            }
            if params.fixed {
                url_builder.append_pair("fixed", "true");
            }
            if params.float {
                url_builder.append_pair("float", "true");
            }
        }
        Ok(url_builder.finish().to_owned())
    }

    async fn send_request<T: DeserializeOwned>(
        &self,
        url: Url,
        method: Method,
        json_params: Option<ExchangeRequest>,
    ) -> Result<T, Error> {
        #[cfg(feature = "log")]
        log::debug!("Sending {method} request to {url}");
        #[cfg(feature = "log")]
        log::debug!("Params: {json_params:#?}");
        let request = self.client.request(method, url);
        let request = match json_params {
            Some(json_params) => request.json(&json_params),
            None => request,
        };
        let response = request.send().await?;
        match response.error_for_status_ref() {
            Ok(_) => Ok(response.json().await?),
            Err(err) => {
                let status = err.status();
                match status {
                    Some(status) => {
                        let text = response.text().await?;
                        Err((status, text).into())
                    }
                    None => Err(err.into()),
                }
            }
        }
    }

    /// Get all available currencies
    /// https://swapspace.co/api/v2/currencies
    /// This API endpoint returns the list of available currencies.
    /// ```
    /// use swapspace_api::SwapSpaceApi;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let response = SwapSpaceApi::default().get_currencies().await.unwrap();
    /// assert_eq!(response.len() > 0, true);
    /// # }
    /// ```
    pub async fn get_currencies(&self) -> Result<Currencies, Error> {
        let url = self.get_full_url("currencies", None)?;
        self.send_request(url, Method::GET, None).await
    }

    /// Get all available amounts
    /// https://swapspace.co/api/v2/amounts
    /// This endpoint has five required (fromCurrency, fromNetwork, toCurrency , toNetwork and amount) and three optional parameters (partner, fixed and float).
    /// If you create a request containing only five required parameters, it will return the list of all the available amounts from all the partners.
    /// If you fill in the partner parameter, it will return the list of amounts available for a specific partner.
    /// If you fill in the fixed field with a true value, the request will return a list of amounts for fixed rate exchanges.
    /// If you fill in the float field with a true value, the request will return a list of amounts for floating rate exchanges.
    /// If you fill in a true value both for fixed and float fields, the request will return amounts both for fixed and floating rate exchanges.
    /// The unit for duration is the minute. The range of values for the supportRate field is from 0 to 3.
    /// ```
    /// use swapspace_api::{SwapSpaceApi, GetAmounts};
    /// # #[tokio::main]
    /// # async fn main() {
    /// let amounts = GetAmounts {
    ///   from_currency: "btc".to_string(),
    ///   from_network: "btc".to_string(),
    ///   to_currency: "eth".to_string(),
    ///   to_network: "eth".to_string(),
    ///   amount: 0.1,
    ///   partner: None,
    ///   fixed: false,
    ///   float: false,
    /// };
    /// let response = SwapSpaceApi::default().get_amounts(&amounts).await.unwrap();
    /// assert_eq!(response.len() > 0, true);
    /// # }
    /// ```
    pub async fn get_amounts(&self, get_amounts: &GetAmounts) -> Result<Amounts, Error> {
        let url = self.get_full_url("amounts", Some(get_amounts))?;
        self.send_request(url, Method::GET, None).await
    }

    /// Get the best amount
    /// https://swapspace.co/api/v2/amounts/best
    /// This endpoint has five required (fromCurrency, fromNetwork, toCurrency , toNetwork and amount) and three optional parameters (partner, fixed and float).
    /// If you create a request containing only five required parameters, it will return the best of all the available amounts from all the partners.
    /// If you fill in the partner parameter, it will return the best amount available for a specific partner.
    /// If you fill in the fixed field with a true value, the request will return a best amount for fixed rate exchanges.
    /// If you fill in the float field with a true value, the request will return a best amount for floating rate exchanges.
    /// If you fill in a true value both for fixed and float fields, the request will return the best amount both for fixed and floating rate exchanges.
    /// The unit for duration is the minute.
    /// The range of values for the supportRate field is from 0 to 3.
    /// ```
    /// use swapspace_api::{SwapSpaceApi, GetAmounts};
    /// # #[tokio::main]
    /// # async fn main() {
    /// let amounts = GetAmounts {
    ///  from_currency: "btc".to_string(),
    ///  from_network: "btc".to_string(),
    ///  to_currency: "eth".to_string(),
    ///  to_network: "eth".to_string(),
    ///  amount: 0.1,
    ///  partner: None,
    ///  fixed: false,
    ///  float: false,
    ///  };
    ///  let response = SwapSpaceApi::default().get_amounts_best(&amounts).await.unwrap();
    ///  assert_eq!(response.exists, true);
    ///  # }
    ///  ```
    pub async fn get_amounts_best(
        &self,
        get_amounts: &GetAmounts,
    ) -> Result<AmountResponse, Error> {
        let url = self.get_full_url("amounts/best", Some(get_amounts))?;
        self.send_request(url, Method::GET, None).await
    }

    /// Get all available partners
    /// https://swapspace.co/api/v2/partners
    /// This API endpoint returns the list of available partners.
    /// ```
    /// use swapspace_api::SwapSpaceApi;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let response = SwapSpaceApi::default().get_partners().await.unwrap();
    /// assert_eq!(response.len() > 0, true);
    /// # }
    /// ```
    pub async fn get_partners(&self) -> Result<Partners, Error> {
        let url = self.get_full_url("partners", None)?;
        self.send_request(url, Method::GET, None).await
    }

    /// Post an exchange
    /// https://swapspace.co/api/v2/exchange
    /// All the fields mentioned in body are required.
    /// Field extraId is required only if the currency you want to receive has hasExtraId: true property (you get this info via the List of currencies endpoint).
    /// If hasExtraId: false, use empty string in the extraId field.
    /// All the fields mentioned in body are required.
    /// Field extraId must be filled in if the value of the hasExtraId field is true in the endpoint List of currencies for this currency.
    /// Otherwise, fill in the extraId field with an empty string.
    /// After userIp fill in the user’s IP in IPv4 or IPv6 format.
    /// Refund field is required if fixed: true and reqFixedRefund: true for relevant partner and float: true and reqFloatRefund: true for relevant partner (look List of partners example response).
    /// But we strongly recommend that you specify refund when creating an exchange, even if it is not required (if a refund is not required or you cannot specify it, then it is permissible to use a refund: '').
    /// ```
    /// use swapspace_api::{SwapSpaceApi, ExchangeRequest, Address};
    /// # #[tokio::main]
    /// # async fn main() {
    ///  let data = ExchangeRequest {
    ///     partner: "simpleswap".to_string(),
    ///     from_currency: "btc".to_string(),
    ///     from_network: "btc".to_string(),
    ///     to_currency: "eth".to_string(),
    ///     to_network: "eth".to_string(),
    ///     address: Address("0x32be343b94f860124dc4fee278fdcbd38c102d88".to_string()),
    ///     amount: 2.0,
    ///     fixed: true,
    ///     extra_id: "".to_string(),
    ///     rate_id: "".to_string(),
    ///     user_ip: "8.8.8.8".to_string(),
    ///     refund: Address("1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX".to_string()),
    ///  };
    ///  let response = SwapSpaceApi::default().post_exchange(data).await.unwrap();
    ///  assert_eq!(response.id.len() > 0, true);
    ///  # }
    pub async fn post_exchange(&self, data: ExchangeRequest) -> Result<ExchangeResponse, Error> {
        let url = self.get_full_url("exchange", None)?;
        self.send_request(url, Method::POST, Some(data)).await
    }

    /// Get exchange status
    /// https://swapspace.co/api/v2/exchange/{id}
    /// Use the Exchange status endpoint to get the current exchange status.
    /// As a request data, use path parameter id, which is to be filled in with exchange id you get with the other data for the successful Create new exchange request.
    /// ```
    /// use swapspace_api::SwapSpaceApi;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let id = "-9mVIXNbYZcG";
    /// let response = SwapSpaceApi::default().get_exchange_status(id).await.unwrap();
    /// assert_eq!(response.id, id);
    /// # }
    /// ```
    pub async fn get_exchange_status(&self, id: &str) -> Result<ExchangeResponse, Error> {
        let url = self.get_full_url(&format!("exchange/{}", id), None)?;
        self.send_request(url, Method::GET, None).await
    }
}
