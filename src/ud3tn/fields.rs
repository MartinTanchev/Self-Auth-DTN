// AAP 2.0 protobuf field numbers and enum values used by `ud3tn`.
//
// GENERATED-OR-CHECKED by integrations/ud3tn/gen_fields.py from uD3TN's
// components/aap2/aap2.proto. The values below were written from the
// published AAP 2.0 reference (names and order, no numbers) and then
// confirmed against uD3TN's aap2.proto on 2026-11-07. Recheck after a uD3TN
// upgrade:
//
//   python3 integrations/ud3tn/gen_fields.py $UD3TN/components/aap2/aap2.proto --check
//   python3 integrations/ud3tn/gen_fields.py $UD3TN/components/aap2/aap2.proto > src/ud3tn/fields.rs
//
// proto-source: checked 2026-11-07

// message AAPMessage { oneof msg { ... } }
pub const AAP_MESSAGE_WELCOME: u32 = 1;
pub const AAP_MESSAGE_CONFIG: u32 = 2;
pub const AAP_MESSAGE_ADU: u32 = 3;
pub const AAP_MESSAGE_KEEPALIVE: u32 = 6;

// message AAPResponse
pub const AAP_RESPONSE_RESPONSE_STATUS: u32 = 1;

// message Welcome
pub const WELCOME_NODE_ID: u32 = 1;

// message ConnectionConfig
pub const CONNECTION_CONFIG_IS_SUBSCRIBER: u32 = 1;
pub const CONNECTION_CONFIG_AUTH_TYPE: u32 = 2;
pub const CONNECTION_CONFIG_SECRET: u32 = 3;
pub const CONNECTION_CONFIG_ENDPOINT_ID: u32 = 4;
pub const CONNECTION_CONFIG_KEEPALIVE_SECONDS: u32 = 5;

// message BundleADU
pub const BUNDLE_ADU_SRC_EID: u32 = 1;
pub const BUNDLE_ADU_DST_EID: u32 = 2;
pub const BUNDLE_ADU_CREATION_TIMESTAMP_MS: u32 = 3;
pub const BUNDLE_ADU_SEQUENCE_NUMBER: u32 = 4;
pub const BUNDLE_ADU_PAYLOAD_LENGTH: u32 = 5;
pub const BUNDLE_ADU_ADU_FLAGS: u32 = 6;

// enum ResponseStatus
pub const RESPONSE_STATUS_SUCCESS: u64 = 1;
pub const RESPONSE_STATUS_ACK: u64 = 2;

// enum AuthType
pub const AUTH_TYPE_DEFAULT: u64 = 0;

// enum BundleADUFlags
pub const BUNDLE_ADU_NORMAL: u64 = 0;
